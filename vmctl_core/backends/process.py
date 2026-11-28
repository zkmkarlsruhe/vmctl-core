"""Generic process backend: an emulator that is an ordinary program, not a libvirt domain.

Works for anything started from one command line on a real or virtual X display, such as
MAME or FS-UAE. The definition lives in ``<instance_dir>/process.json`` (see
:class:`ProcessSpec`).

A snapshot is a cold copy of the writable images with SHA-256 sums: revert stops the process,
verifies the copy and restores it. There is no RAM state. Starting after a revert boots the
machine, as a power cycle does. The sums make a damaged baseline fail closed instead of
booting it.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import BaseModel, Field, model_validator

from vmctl_core.atomicio import write_text_atomic
from vmctl_core.backends.base import BackendError, checked_snapshot_name
from vmctl_core.catalog import BaseImage
from vmctl_core.introspect.liveness import probe
from vmctl_core.paths import safe_segment

SPEC_FILE = "process.json"
STOP_TIMEOUT_S = 5.0
DISPLAY_TIMEOUT_S = 5.0
_CHUNK = 1024 * 1024


class ProbeSpec(BaseModel):
    """Read-only guest probe; Kickstart is relative to the instance directory."""

    kind: Literal["amiga", "mac68k"]
    kickstart: str = ""
    ram_bytes: int = Field(default=0, ge=0)
    expect: list[str] = Field(default_factory=list)
    max_age_s: float = Field(default=10, gt=0, allow_inf_nan=False)

    @model_validator(mode="after")
    def validate_probe(self) -> Self:
        if self.kind == "amiga":
            path = Path(self.kickstart)
            if not self.kickstart or path.is_absolute() or ".." in path.parts or path == Path("."):
                raise ValueError("amiga probe needs an instance-relative kickstart path")
        elif self.ram_bytes < 0x930 or self.ram_bytes % 4:
            raise ValueError("mac68k probe needs ram_bytes >= 0x930 aligned to four bytes")
        if any(not name.strip() for name in self.expect):
            raise ValueError("expected program names must not be empty")
        return self


class ProcessSpec(BaseModel):
    """What to run. Relative image paths and ``cwd`` resolve against the instance directory.

    ``media`` maps instance-relative names to pinned host prerequisites at clone time.
    Bundles replace those host paths with local names; argv/env use the local names.
    """

    argv: list[str]
    env: dict[str, str] = Field(default_factory=dict)
    cwd: str = ""
    display: str = ":0"  # X display for the emulator window and for screenshots
    virtual_display: bool = False
    screen: str = "1024x768x24"
    vnc_port: int = 0
    media: dict[str, str] = Field(default_factory=dict)
    media_sha256: dict[str, str] = Field(default_factory=dict)
    images: list[str] = Field(default_factory=list)  # writable files a snapshot captures
    # a file the emulated work touches while it runs; empty = process alive counts as alive
    alive_file: str = ""
    alive_max_age_s: float = 5.0
    probe: ProbeSpec | None = None


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


def _display_accepts_clients(path: str) -> bool:
    try:
        with socket.socket(socket.AF_UNIX) as client:
            client.settimeout(0.1)
            client.connect(path)
        return True
    except OSError:
        return False


def process_path(root: Path, name: str) -> Path:
    """Confine portable process payload names without following media symlinks."""
    path = Path(name)
    if (
        not name
        or name != name.strip()
        or path.is_absolute()
        or ".." in path.parts
        or not path.parts
        or any(c in name for c in "\n\r\\")
        or path.parts[0]
        in {SPEC_FILE, "process.pid", "process.emulator.pid", "process.log", "snapshots"}
    ):
        raise BackendError(f"invalid process payload path: {name!r}")
    return root / path


def clone_process(
    base: BaseImage,
    *,
    catalog_dir: Path,
    domain_name: str,
    instance_dir: Path,
    display_num: int,
    vnc_port: int,
    spec_dir: Path,
) -> tuple[Path, Path]:
    """Copy raw goldens and link pinned host media into a new process instance.

    Relative golden names keep their catalog-relative layout; absolute goldens use
    their basename. The argv/env template must use these instance-relative names.
    The returned definition is spec_dir/<domain>.process.json; a copy at
    instance_dir/process.json lets ProcessBackend load it directly.
    """
    safe_segment(domain_name, field="domain_name")
    instance_dir, spec_dir = Path(instance_dir).absolute(), Path(spec_dir).absolute()
    catalog_dir = Path(catalog_dir).absolute()
    spec = ProcessSpec.model_validate(base.hw.process)
    sources: dict[str, Path] = {}
    for name in [base.path, *spec.images]:
        source = Path(name)
        local = source.name if source.is_absolute() else name
        process_path(instance_dir, local)
        source = catalog_dir / source
        if local in sources and sources[local] != source:
            raise BackendError(f"duplicate process image name: {local}")
        sources[local] = source
    for name, media_source in spec.media.items():
        process_path(instance_dir, name)
        if name in sources:
            raise BackendError(f"process media conflicts with image: {name}")
        if not Path(media_source).is_absolute():
            raise BackendError(f"process media must have an absolute host path: {name}")
        want = spec.media_sha256.get(name, "")
        if not want or _sha256(Path(media_source)) != want.lower():
            raise BackendError(f"process media sha256 mismatch: {name} ({media_source})")
    if spec.cwd and spec.cwd != ".":
        process_path(instance_dir, spec.cwd)
    if spec.alive_file:
        process_path(instance_dir, spec.alive_file)
    spec.images = list(sources)
    spec.display = f":{display_num}"
    spec.virtual_display = True
    spec.vnc_port = vnc_port
    definition = spec.model_dump_json(indent=2)
    spec_path = spec_dir / f"{domain_name}.process.json"
    if spec_path.exists():
        raise BackendError(f"process definition already exists: {spec_path}")
    instance_dir.mkdir(parents=True)  # never overwrite an existing instance
    try:
        for name, source in sources.items():
            target = process_path(instance_dir, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            target.chmod(target.stat().st_mode | 0o200)
        for name, media_source in spec.media.items():
            target = process_path(instance_dir, name)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(media_source)
        if spec.cwd:
            (instance_dir / spec.cwd).mkdir(parents=True, exist_ok=True)
        write_text_atomic(instance_dir / SPEC_FILE, definition)
        write_text_atomic(spec_path, definition)
    except BaseException:
        shutil.rmtree(instance_dir)
        raise
    return instance_dir / spec.images[0], spec_path


class ProcessBackend:
    """One emulator process group bound to one instance directory."""

    def __init__(
        self, name: str, *, instance_dir: str | Path, spec: ProcessSpec | None = None
    ) -> None:
        self.name = name
        self.instance_dir = Path(instance_dir)
        self.spec = spec or ProcessSpec.model_validate_json(
            (self.instance_dir / SPEC_FILE).read_text()
        )
        self._lock = threading.RLock()
        self._probe_state: dict[str, Any] = {}
        self._probe_pid: int | None = None

    # --- paths ------------------------------------------------------------
    @property
    def _pid_path(self) -> Path:
        return self.instance_dir / "process.pid"

    @property
    def _snapshots(self) -> Path:
        return self.instance_dir / "snapshots"

    def _resolve(self, path: str) -> Path:
        return self.instance_dir / path

    # --- existence & state ------------------------------------------------
    def exists(self) -> bool:
        return self.instance_dir.is_dir() and all(
            self._resolve(p).exists() for p in self.spec.images
        )

    def _pid(self) -> int | None:
        try:
            path = (
                self.instance_dir / "process.emulator.pid"
                if self.spec.virtual_display
                else self._pid_path
            )
            pid = int(path.read_text())
        except (OSError, ValueError):
            return None
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return None
        except PermissionError:
            return pid
        # a pid the kernel reused for a dead group leader is not ours
        try:
            state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        except OSError:
            return None
        return None if state == "Z" else pid

    def is_running(self) -> bool:
        return self._pid() is not None

    def state(self) -> str:
        if self.is_running():
            return "running"
        return "shut off" if self.exists() else "undefined"

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        with self._lock:
            if self.is_running():
                return
            self.stop()  # helpers of a crashed run hold ports and devices
            if not self.exists():
                raise BackendError(f"{self.name}: instance is incomplete in {self.instance_dir}")
            if self.spec.alive_file:
                self._resolve(self.spec.alive_file).unlink(missing_ok=True)
            env = {**os.environ, "DISPLAY": self.spec.display, **self.spec.env}
            cwd = self._resolve(self.spec.cwd) if self.spec.cwd else self.instance_dir
            if self.spec.virtual_display:
                env["DISPLAY"] = self.spec.display
                self._start_virtual(cwd, env)
                return
            with (self.instance_dir / "process.log").open("ab") as log:
                try:
                    proc = subprocess.Popen(
                        self.spec.argv,
                        cwd=cwd,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        start_new_session=True,  # own group, so stop() also ends helpers
                    )
                except OSError as e:
                    raise BackendError(f"{self.name}: cannot start: {e}") from e
            self._pid_path.write_text(str(proc.pid))
            threading.Thread(target=proc.wait, daemon=True).start()  # reap, no zombie

    def _start_virtual(self, cwd: Path, env: dict[str, str]) -> None:
        if not re.fullmatch(r":\d+(?:\.\d+)?", self.spec.display):
            raise BackendError(f"invalid virtual display: {self.spec.display!r}")
        if not 1 <= self.spec.vnc_port <= 65535:
            raise BackendError("virtual display needs a VNC port between 1 and 65535")
        display_num = self.spec.display[1:].split(".")[0]
        socket_path = f"/tmp/.X11-unix/X{display_num}"
        if _display_accepts_clients(socket_path):
            raise BackendError(f"{self.name}: display {self.spec.display} already in use")
        procs: list[subprocess.Popen] = []
        try:
            with (self.instance_dir / "process.log").open("ab") as log:

                def launch(argv: list[str]) -> subprocess.Popen:
                    proc = subprocess.Popen(
                        argv,
                        cwd=cwd,
                        env=env,
                        stdin=subprocess.DEVNULL,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        process_group=procs[0].pid if procs else 0,
                    )
                    procs.append(proc)
                    return proc

                xvfb = launch(
                    [
                        "Xvfb",
                        self.spec.display,
                        "-screen",
                        "0",
                        self.spec.screen,
                        "-nolisten",
                        "tcp",
                    ]
                )
                self._pid_path.write_text(str(xvfb.pid))
                deadline = time.monotonic() + DISPLAY_TIMEOUT_S
                while True:
                    if xvfb.poll() is not None:
                        raise BackendError(f"{self.name}: Xvfb exited during display startup")
                    if _display_accepts_clients(socket_path):
                        break
                    if time.monotonic() >= deadline:
                        raise BackendError(f"{self.name}: display {self.spec.display} not ready")
                    time.sleep(0.05)
                launch(
                    [
                        "x11vnc",
                        "-display",
                        self.spec.display,
                        "-localhost",
                        "-forever",
                        "-shared",
                        "-rfbport",
                        str(self.spec.vnc_port),
                    ]
                )
                emulator = launch(self.spec.argv)
                (self.instance_dir / "process.emulator.pid").write_text(str(emulator.pid))
                for proc in procs:
                    if proc.poll() is not None:
                        raise BackendError(f"{self.name}: {proc.args!r} exited during startup")
        except BaseException as e:
            if procs:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(procs[0].pid, signal.SIGKILL)
                for proc in procs:
                    proc.wait()
            self._pid_path.unlink(missing_ok=True)
            (self.instance_dir / "process.emulator.pid").unlink(missing_ok=True)
            if isinstance(e, OSError):
                raise BackendError(f"{self.name}: cannot start: {e}") from e
            raise
        for proc in procs:
            threading.Thread(target=proc.wait, daemon=True).start()

    def stop(self) -> None:
        with self._lock:
            self._probe_state.clear()
            self._probe_pid = None
            try:
                pid = int(self._pid_path.read_text())
            except (OSError, ValueError):
                return
            try:
                os.killpg(pid, signal.SIGTERM)
                end = time.monotonic() + STOP_TIMEOUT_S
                while time.monotonic() < end and self.is_running():
                    time.sleep(0.05)
            except ProcessLookupError:
                pass
            with contextlib.suppress(ProcessLookupError):
                os.killpg(pid, signal.SIGKILL)  # also a frozen helper that outlived the leader
            while self.is_running():
                time.sleep(0.05)
            self._pid_path.unlink(missing_ok=True)
            if self.spec.virtual_display:
                (self.instance_dir / "process.emulator.pid").unlink(missing_ok=True)

    def shutdown(self) -> None:
        self.stop()

    def reboot(self) -> None:
        self.reset()

    def reset(self) -> None:
        with self._lock:
            self.stop()
            self.start()

    # --- settings: fixed by the spec -------------------------------------
    def get_settings(self) -> dict:
        return {"state": self.state(), "persistent": True}

    def set_settings(
        self,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        autostart: bool | None = None,
    ) -> None:
        raise BackendError(f"{self.name}: settings are fixed in {SPEC_FILE}")

    def tap_interface(self) -> str | None:
        return None

    def discover_vm_network(self) -> str | None:
        return None  # the emulated machine is not a guest on a host network

    def define(self, xml_path: str) -> None:
        raise BackendError(f"{self.name}: no domain XML, the definition is {SPEC_FILE}")

    def undefine(self) -> None:
        raise BackendError(f"{self.name}: no domain to undefine")

    # --- snapshots: cold image copies ------------------------------------
    def snapshot_list(self) -> list[str]:
        if not self._snapshots.is_dir():
            return []
        return sorted(p.parent.name for p in self._snapshots.glob("*/SHA256SUMS"))

    def snapshot_create(self, name: str, *, memory: bool = True) -> None:
        """Replace snapshot ``name`` with a copy of the images, atomically: a failure leaves
        the previous snapshot in place. ``memory`` has no effect, there is no RAM state."""
        name = checked_snapshot_name(name)
        with self._lock:
            if self.is_running():
                raise BackendError(f"{self.name}: stop the emulator before a snapshot")
            target = self._snapshots / name
            staging = self._snapshots / f".{name}.staging"
            shutil.rmtree(staging, ignore_errors=True)
            staging.mkdir(parents=True)
            sums = {}
            for image in self.spec.images:
                copy = staging / image
                copy.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(self._resolve(image), copy)
                sums[image] = _sha256(copy)
            (staging / "SHA256SUMS").write_text(json.dumps(sums, indent=1))
            retired = self._snapshots / f".{name}.retired"
            shutil.rmtree(retired, ignore_errors=True)
            if target.exists():
                target.rename(retired)
            staging.rename(target)
            shutil.rmtree(retired, ignore_errors=True)

    def snapshot_revert(self, name: str) -> None:
        """Restore the images, verified. Leaves the emulator stopped."""
        name = checked_snapshot_name(name)
        with self._lock:
            source = self._snapshots / name
            if name not in self.snapshot_list():
                raise BackendError(f"{self.name}: no snapshot {name!r}")
            self.stop()
            sums = json.loads((source / "SHA256SUMS").read_text())
            for image, want in sums.items():
                if _sha256(source / image) != want:
                    raise BackendError(f"{self.name}: snapshot {name!r} damaged: {image}")
            for image in sums:
                tmp = self._resolve(image).with_name(self._resolve(image).name + ".restore")
                shutil.copy2(source / image, tmp)
                tmp.replace(self._resolve(image))

    def snapshot_delete(self, name: str) -> None:
        name = checked_snapshot_name(name)
        with self._lock:
            if name not in self.snapshot_list():
                raise BackendError(f"{self.name}: no snapshot {name!r}")
            shutil.rmtree(self._snapshots / name)

    # --- screen -----------------------------------------------------------
    def screenshot(self, screen: int = 0) -> bytes:
        argv = ["ffmpeg", "-loglevel", "error", "-f", "x11grab", "-i", self.spec.display]
        argv += ["-frames:v", "1", "-f", "image2pipe", "-c:v", "png", "-"]
        try:
            return subprocess.run(argv, capture_output=True, check=True, timeout=15).stdout
        except (OSError, subprocess.SubprocessError) as e:
            raise BackendError(f"{self.name}: screenshot failed: {e}") from e

    def vnc_endpoint(self) -> tuple[str, int | str] | None:
        return ("127.0.0.1", self.spec.vnc_port) if self.spec.virtual_display else None

    def send_key(self, keys: list[str]) -> None:
        raise BackendError(f"{self.name}: key injection is not supported")

    def insert_cd(self, iso_path: str) -> None:
        raise BackendError(f"{self.name}: no CD-ROM")

    def eject_cd(self) -> None:
        raise BackendError(f"{self.name}: no CD-ROM")

    # --- liveness instead of a guest agent ------------------------------
    def _probe_candidates(self, leader: int) -> list[int]:
        """Search the recorded process's group and descendants, including new groups.

        Prefer fs-uae or argv[0]'s basename (Linux comm is limited to 15 bytes), then
        try remaining members in PID order. Successful RAM discovery selects the owner.
        """
        try:
            group = os.getpgid(leader)
        except ProcessLookupError:
            return []
        binary = Path(self.spec.argv[0]).name if self.spec.argv else ""
        names = {"fs-uae", binary[:15]}
        processes: dict[int, tuple[int, int, str]] = {}
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                # proc_pid_stat(5): fields 4/5 are PPID/PGRP; comm can contain ')'.
                stat = (entry / "stat").read_text().rsplit(")", 1)[1].split()
                processes[int(entry.name)] = (
                    int(stat[1]),
                    int(stat[2]),
                    (entry / "comm").read_text().strip(),
                )
            except (OSError, ValueError, IndexError):
                continue
        descendants = {leader}
        while children := {
            pid
            for pid, (parent, _, _) in processes.items()
            if parent in descendants and pid not in descendants
        }:
            descendants.update(children)
        candidates = [
            (comm not in names, pid)
            for pid, (_, pgrp, comm) in processes.items()
            if pgrp == group or pid in descendants
        ]
        return [pid for _, pid in sorted(candidates)]

    def _guest_probe(self, leader: int) -> tuple[bool | None, dict]:
        assert self.spec.probe is not None
        spec = self.spec.probe
        if spec.kind == "amiga":
            spec = spec.model_copy(update={"kickstart": str(self._resolve(spec.kickstart))})
        candidates = self._probe_candidates(leader)
        if self._probe_pid in candidates:
            candidates.remove(self._probe_pid)
            candidates.insert(0, self._probe_pid)
        detail = {"alive": False, "status": "unreadable", "reason": "no emulator RAM found"}
        denied: PermissionError | None = None
        for pid in candidates:
            try:
                alive, detail = probe(spec, pid, self._probe_state)
            except PermissionError as exc:
                denied = exc
                continue
            if detail.get("status") == "ok":
                self._probe_pid = pid
                return alive, detail
        self._probe_pid = None
        self._probe_state.clear()
        if denied is not None:
            raise BackendError(
                f"{self.name}: cannot read emulator memory: {denied}; check "
                "kernel.yama.ptrace_scope (use the emulator's parent, CAP_SYS_PTRACE, "
                "or an appropriately configured ptrace policy)"
            ) from denied
        self._probe_state["detail"] = detail
        return False, detail

    def guest_ping(self, timeout: float = 5.0) -> bool:
        """Require a running process, configured probe, and optional fresh alive file.

        Warming up is False here to preserve the backend's boolean contract; the
        latest detail returned by guest_tasks retains alive=None and its reason.
        """
        with self._lock:
            pid = self._pid()
            if pid is None:
                self._probe_state.clear()
                self._probe_pid = None
                return False
            alive = self._guest_probe(pid)[0] is True if self.spec.probe else True
            if self.spec.alive_file:
                try:
                    age = time.time() - self._resolve(self.spec.alive_file).stat().st_mtime
                except OSError:
                    return False
                alive = alive and age <= self.spec.alive_max_age_s
            return alive

    def guest_tasks(self) -> dict:
        """Return the last probe detail without advancing its liveness baseline.

        A first call obtains a sample. Further refreshes happen through guest_ping.
        """
        with self._lock:
            if not self.spec.probe:
                return {}
            if not self.is_running():
                self._probe_state.clear()
                self._probe_pid = None
                return {"alive": False, "status": "stopped"}
            if "detail" not in self._probe_state:
                self.guest_ping()
            return dict(self._probe_state.get("detail", {}))

    def guest_exec(
        self, path: str, args: list[str] | None = None, *, timeout: float = 15.0
    ) -> tuple[int, str, str]:
        raise BackendError(f"{self.name}: no guest agent")

    def guest_write_file(self, guest_path: str, data: bytes) -> None:
        raise BackendError(f"{self.name}: no guest agent")

    def guest_read_file(self, guest_path: str) -> bytes:
        raise BackendError(f"{self.name}: no guest agent")

    def net_info(self) -> dict:
        return {}
