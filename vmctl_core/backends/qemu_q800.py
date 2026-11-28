"""Quadra 800 (68k Mac) VMBackend: ``qemu-system-m68k -M q800`` as a process, normally
inside the golden's pinned emulator container image.

Why not libvirt: libvirt 12.7.0 refuses to define ANY m68k domain ("Machine type
'q800' supports PCI but no PCI controller added" — ``qemuDomainSupportsPCI`` treats
every arch it does not list as PCI-capable; research/70c §7.1). Until that is
patched upstream, a q800 base runs here, next to the SheepShaver/Basilisk process
backends (``mac_emu``). Unlike those, QEMU brings its own VNC server and QMP, so
there is no Xvfb/x11vnc trio: one QEMU process per instance.

Emulator image (research/70j): a base that sets ``hw.emulator_image_id`` (the sha256 image
id of e.g. ``vmctl-emu/qemu-m68k:11.1.1-zkm1``) runs QEMU with ``docker run <image id>``,
so every golden keeps the exact QEMU it was built and verified on, and the host needs only
docker. One container per instance (``--network none``, all caps dropped, read-only root,
only the instance's files bind-mounted at their host paths; labels ``vmctl.kind=q800``,
``vmctl.instance``, ``vmctl.instance-dir``). Without an image the host binary
(``VMCTL_QEMU_M68K_BIN``) runs directly: the fallback, e.g. for tests.

One instance == one directory (``instance_dir``)::

    instance.json   the definition (disk, PRAM, ROM, memory, CD, NIC, image) == "domain XML"
    runtime.json    pid (+ container name) of the running QEMU
    pram.qcow2      per-instance PRAM overlay (created by :func:`clone_q800`)
    qmp.sock        QMP monitor;  serial-a.sock / serial-b.sock  ESCC channels A/B
    vnc.sock        VNC (websockify target ``unix_socket:<path>``)
    agent.sock      SLiRP hostfwd to the agent's guest :9009 (unix socket, libslirp >= 4.7)
    qemu.log        QEMU stdout/stderr

What it gives the controller (research/70b/70c):

* live snapshots: HMP ``savevm``/``loadvm``/``delvm`` over QMP. Every writable drive
  must be qcow2, so the disk AND the PRAM are qcow2 (a raw ``if=mtd`` PRAM blocks
  ``savevm``, 70c §7.4).
* screendump PNG and ``send-key`` over QMP (no guest cooperation).
* the in-guest agent ``rvmc-68k`` (vmctl-guest-agent/mac68k): VA1 on
  guest :9009, reached through a SLiRP ``hostfwd`` on the instance's unix socket,
  falling back to VA1 on the ESCC printer port (B).
* clean power-off: the ADB power key opens "Are you sure you want to shut down?",
  Return confirms, QEMU exits 0. ACPI ``system_powerdown`` does nothing on a q800.

The ROM is a HOST prerequisite (``VMCTL_ROM_68K`` or the base's ``hw.rom``), never part
of a base image or bundle. ``hw.rom_checksum`` / ``hw.rom_sha256`` pin the dump.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import threading
import time
import uuid
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import Any

from vmctl_core.agentwire import AgentClient, Reply, TCPTransport, UnixTransport
from vmctl_core.atomicio import write_text_atomic
from vmctl_core.backends._agent import AgentUnreachable, agent_session
from vmctl_core.backends.base import BackendError, checked_snapshot_name
from vmctl_core.backends.mac_emu import MacEmuSettings
from vmctl_core.paths import safe_segment

AGENT_PORT = 9009  # guest-side VA1 TCP port
# classicvirtio declaration ROM inside the vmctl-emu/qemu-m68k images (absolute tablet)
DECLROM_IN_IMAGE = "/usr/local/share/vmctl/classicvirtio-declrom"
# AF_UNIX sun_path is 108 bytes on Linux; QEMU fails late and cryptically past it.
_SUN_PATH_MAX = 107
_SNAP_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9._-]{0,63}")  # one HMP token for savevm

# Per-instance locks shared by every Q800Backend object bound to the same directory:
# the controller builds a fresh backend per request, and both QMP (one client at a time)
# and the 68k agent (3 MacTCP listen streams, no backlog — 70c §8.3) want serialized use.
_LOCKS: dict[tuple[str, str], threading.RLock] = {}
_LAST_AGENT_CALL: dict[str, float] = {}  # instance_dir -> monotonic time of the last agent call
# ponytail: fixed settle before savevm. A snapshot taken while rvmc-agent-68k is still closing
# the previous MacTCP connection was the measured pattern behind post-loadvm agent loss
# (quiesced: 0/120 cycles, not quiesced: ~1/115 on QEMU 11.0.2, research/70e 4.2). Upgrade
# path: an agent-side "quiesce" tool that reports its streams idle.
SNAPSHOT_QUIESCE_S = 2.0
# clean shut-down ladder (agent -> cmd-q -> power key -> hard stop): wait per step,
# Cmd-Q rounds (one per app in front) and the pause after each Cmd-Q
SHUTDOWN_STEP_S = 20.0
SHUTDOWN_CMDQ_ROUNDS = 4
SHUTDOWN_CMDQ_WAIT_S = 3.0
_LOCKS_GUARD = threading.Lock()


def _lock(instance_dir: Path, kind: str) -> threading.RLock:
    key = (str(instance_dir), kind)
    with _LOCKS_GUARD:
        # re-entrant: revert -> start, reset -> stop + start run under the same "life" lock
        return _LOCKS.setdefault(key, threading.RLock())


# libvirt/linux KEY_* names -> QEMU qcodes. Unmapped KEY_X falls back to "x"
# (letters, digits, f1..f12 match QEMU's qcode names directly).
_QCODES = {
    "KEY_ESC": "esc",
    "KEY_ENTER": "ret",
    "KEY_KPENTER": "kp_enter",
    "KEY_TAB": "tab",
    "KEY_SPACE": "spc",
    "KEY_BACKSPACE": "backspace",
    "KEY_DELETE": "delete",
    "KEY_UP": "up",
    "KEY_DOWN": "down",
    "KEY_LEFT": "left",
    "KEY_RIGHT": "right",
    "KEY_HOME": "home",
    "KEY_END": "end",
    "KEY_PAGEUP": "pgup",
    "KEY_PAGEDOWN": "pgdn",
    "KEY_LEFTCTRL": "ctrl",
    "KEY_RIGHTCTRL": "ctrl_r",
    "KEY_LEFTALT": "alt",
    "KEY_RIGHTALT": "alt_r",
    "KEY_LEFTSHIFT": "shift",
    "KEY_RIGHTSHIFT": "shift_r",
    "KEY_LEFTMETA": "meta_l",  # the Mac Command key
    "KEY_RIGHTMETA": "meta_r",
    "KEY_POWER": "power",  # ADB power key -> the shut-down dialog
    "KEY_MINUS": "minus",
    "KEY_EQUAL": "equal",
    "KEY_DOT": "dot",
    "KEY_COMMA": "comma",
    "KEY_SLASH": "slash",
    "KEY_SEMICOLON": "semicolon",
}


def qcode(name: str) -> str:
    name = str(name).strip()
    if name in _QCODES:
        return _QCODES[name]
    if name.upper().startswith("KEY_"):
        return name[4:].lower()
    return name.lower()


def qcow2_backing_chain(path: str | Path) -> list[Path]:
    """The backing files below a qcow2 image, top-down, resolved the way QEMU does (a
    relative name is relative to the referring image's directory). Raw/other formats
    end the chain. Used to bind-mount exactly the files a containerized QEMU opens."""
    chain: list[Path] = []
    cur = Path(path)
    for _ in range(32):
        try:
            with open(cur, "rb") as f:
                hdr = f.read(20)
                if len(hdr) < 20 or hdr[:4] != b"QFI\xfb":
                    break
                off, size = int.from_bytes(hdr[8:16], "big"), int.from_bytes(hdr[16:20], "big")
                if not off or not size:
                    break
                f.seek(off)
                name = f.read(size).decode("utf-8")
        except OSError as e:
            raise BackendError(f"q800: cannot read {cur}: {e}") from e
        cur = Path(name) if os.path.isabs(name) else cur.parent / name
        chain.append(cur)
    return chain


def pipewire_socket() -> Path:
    """The controller user's PipeWire socket (QEMU's pipewire audiodev connects to it)."""
    return Path(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}") / "pipewire-0"


def docker_user(settings: MacEmuSettings) -> str:
    """``--user`` for emulator containers: the controller's own uid:gid, so files QEMU
    creates (sockets, log, snapshots inside the qcow2s) stay the controller's. Rootless
    docker: set VMCTL_Q800_DOCKER_USER=0:0 (container root == the host user there)."""
    return settings.q800_docker_user or f"{os.getuid()}:{os.getgid()}"


def docker_run_argv(
    settings: MacEmuSettings,
    image: str,
    *,
    rw: Sequence[str | Path] = (),
    ro: Sequence[str | Path] = (),
    name: str = "",
    labels: dict[str, str] | None = None,
    detach: bool = False,
    env: dict[str, str] | None = None,
) -> list[str]:
    """``docker run`` prefix for the pinned emulator image: no network (SLiRP lives in
    QEMU, ``restrict=on``; the host reaches QEMU only through the unix sockets in the
    instance dir), no capabilities, no privilege gain, read-only root, and each host
    path bind-mounted at the SAME path (no path translation in argv or qcow2 headers)."""
    argv = [
        *shlex.split(settings.docker_bin), "run", "--rm", "--network", "none",
        "--user", docker_user(settings), "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/tmp",
    ]  # fmt: skip
    if detach:
        argv.append("-d")
    if name:
        argv += ["--name", name]
    for k, v in (labels or {}).items():
        argv += ["--label", f"{k}={v}"]
    for k, v in (env or {}).items():
        argv += ["-e", f"{k}={v}"]
    seen: set[str] = set()
    for paths, readonly in ((rw, False), (ro, True)):
        for p in paths:
            p = os.path.abspath(str(p))
            if p in seen:
                continue  # rw (listed first) wins
            if "," in p or "\n" in p:
                raise BackendError(f"q800: path not mountable into the emulator container: {p!r}")
            seen.add(p)
            argv += [
                "--mount",
                f"type=bind,source={p},target={p}" + (",readonly" if readonly else ""),
            ]
    return [*argv, image]


def q800_spec(
    base: Any,
    *,
    disk: str | Path,
    pram: str | Path,
    rom: str = "",
    cdrom: str | None = None,
    net: dict | None = None,
) -> dict:
    """The instance definition (the q800 analogue of a rendered domain XML) for a
    catalog base. Pure — no files touched. ``rom`` '' => resolved at start from
    ``hw.rom`` / ``VMCTL_ROM_68K``."""
    hw = base.hw
    return {
        "kind": "q800",
        "base_id": base.id,
        "disk": str(disk),
        "pram": str(pram),
        "rom": rom or (getattr(hw, "rom", "") or ""),
        "rom_checksum": (getattr(hw, "rom_checksum", "") or "").upper(),
        "rom_sha256": (getattr(hw, "rom_sha256", "") or "").lower(),
        "memory_mb": int(hw.memory_mb),
        # q800 `-g WxHxDEPTH`; mac_screen doubles as the q800 graphics mode.
        "graphics": (hw.mac_screen or "640x480x8"),
        "cdrom": cdrom,
        "net": net or {"mode": "user"},
        # the pinned emulator image ('' => host binary); the id is what runs
        "emulator_image": getattr(hw, "emulator_image", "") or "",
        "emulator_image_id": getattr(hw, "emulator_image_id", "") or "",
        # classicvirtio absolute tablet (needs 32-bit addressing in the PRAM, 70g §3)
        "tablet": bool(getattr(hw, "usb_tablet", False)),
    }


def clone_q800(
    base: Any,
    *,
    catalog_dir: Path,
    domain_name: str,
    overlays_dir: Path,
    spec_dir: Path,
    instance_dir: Path,
    rom: str = "",
    qemu_img: str = "qemu-img",
    settings: MacEmuSettings | None = None,
) -> tuple[Path, Path]:
    """Clone a q800 base: a thin qcow2 overlay of the golden disk (in ``overlays_dir``,
    like every other clone) + a PRAM overlay of the golden PRAM inside
    ``instance_dir`` (removed with the instance by ``undefine``), and the definition
    JSON in ``spec_dir``. Returns ``(overlay, spec_path)``. The golden stays read-only.
    A base with ``hw.emulator_image_id`` runs ``qemu-img`` from that image."""
    safe_segment(domain_name, field="domain_name")  # no traversal out of the clone dirs
    # absolute everywhere: these paths go into the spec, qcow2 backing names and container
    # argv, where a path relative to the controller's cwd means nothing (default state .rvmc)
    catalog_dir, overlays_dir = Path(catalog_dir).absolute(), Path(overlays_dir).absolute()
    spec_dir, instance_dir = Path(spec_dir).absolute(), Path(instance_dir).absolute()
    golden = base.resolved_path(catalog_dir)
    nvram = getattr(base.hw, "nvram", "") or ""
    if not nvram:
        raise BackendError(f"base {base.id!r}: q800 needs hw.nvram (the golden PRAM qcow2)")
    golden_pram = (
        Path(nvram) if Path(nvram).is_absolute() else (Path(catalog_dir) / nvram).resolve()
    )
    for p in (golden, golden_pram):
        if not p.exists():
            raise BackendError(f"base {base.id!r}: {p} not found")
    overlays_dir.mkdir(parents=True, exist_ok=True)
    spec_dir.mkdir(parents=True, exist_ok=True)
    instance_dir.mkdir(parents=True, exist_ok=True)
    overlay = overlays_dir / f"{domain_name}.qcow2"
    pram = instance_dir / "pram.qcow2"
    image = getattr(base.hw, "emulator_image_id", "") or ""
    st = settings or MacEmuSettings()
    if qemu_img == "qemu-img":  # not given explicitly: the settings' (VMCTL_QEMU_IMG_BIN) binary
        qemu_img = st.qemu_img_bin
    for src, dst in ((golden, overlay), (golden_pram, pram)):
        cmd = ["qemu-img" if image else qemu_img, "create", "-f", "qcow2", "-F", "qcow2",
               "-b", str(src), str(dst)]  # fmt: skip
        if image:
            ro = [src, *qcow2_backing_chain(src)]
            cmd = [*docker_run_argv(st, image, rw=[dst.parent], ro=ro), *cmd]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise BackendError(f"qemu-img create {dst.name} failed: {p.stderr.strip()}")
    spec_path = spec_dir / f"{domain_name}.q800.json"
    spec_path.write_text(json.dumps(q800_spec(base, disk=overlay, pram=pram, rom=rom), indent=2))
    return overlay, spec_path


class Q800Backend:
    """VMBackend over one ``qemu-system-m68k -M q800`` process (see module doc)."""

    supports_live_snapshot = True

    def __init__(self, name: str, *, instance_dir: str | Path, settings: MacEmuSettings) -> None:
        self.name = name
        self.instance_dir = Path(instance_dir).absolute()  # its paths go into QEMU's argv
        self.settings = settings

    # --- files ------------------------------------------------------------
    @property
    def spec_path(self) -> Path:
        return self.instance_dir / "instance.json"

    @property
    def runtime_path(self) -> Path:
        return self.instance_dir / "runtime.json"

    @property
    def qmp_path(self) -> Path:
        return self.instance_dir / "qmp.sock"

    def serial_path(self, channel: str) -> Path:
        return self.instance_dir / f"serial-{channel}.sock"

    @property
    def vnc_path(self) -> Path:
        return self.instance_dir / "vnc.sock"

    @property
    def agent_sock_path(self) -> Path:
        return self.instance_dir / "agent.sock"

    def _sockets(self) -> tuple[Path, ...]:
        return (self.qmp_path, self.serial_path("a"), self.serial_path("b"), self.vnc_path,
                self.agent_sock_path)  # fmt: skip

    @property
    def container_name(self) -> str:
        """Stable per instance dir: two dirs with the same instance name never collide."""
        tag = hashlib.sha1(str(self.instance_dir.resolve()).encode()).hexdigest()[:8]
        return f"vmctl-q800-{re.sub(r'[^A-Za-z0-9_.-]', '-', self.name)[:40]}-{tag}"

    @staticmethod
    def _image(spec: dict) -> str:
        return str(spec.get("emulator_image_id") or "")

    @property
    def log_path(self) -> Path:
        return self.instance_dir / "qemu.log"

    def spec(self) -> dict:
        try:
            return json.loads(self.spec_path.read_text())
        except FileNotFoundError:
            raise BackendError(f"q800 instance {self.name!r} is not defined") from None

    def _write_spec(self, spec: dict) -> None:
        write_text_atomic(self.spec_path, json.dumps(spec, indent=2))

    def _update_spec(self, **changes: Any) -> dict:
        """Read-modify-write of the definition, serialized per instance (a CD change and a
        memory change racing must not lose one another)."""
        with _lock(self.instance_dir, "spec"):
            spec = self.spec()
            spec.update(changes)
            self._write_spec(spec)
            return spec

    def _runtime(self) -> dict:
        try:
            data = json.loads(self.runtime_path.read_text())
            return data if isinstance(data, dict) else {}
        except (FileNotFoundError, ValueError):
            return {}

    # --- command line -----------------------------------------------------
    def rom_path(self, spec: dict | None = None) -> str:
        spec = spec or self.spec()
        return spec.get("rom") or self.settings.rom_68k

    def build_argv(self, spec: dict, *, loadvm: str = "", agent_tcp: bool = False) -> list[str]:
        """The QEMU argv for this instance (without the docker/launch prefix). Pure (no
        I/O): unit-testable. Every host endpoint is a unix socket in ``instance_dir``.
        ``agent_tcp``: forward the agent to the container's own loopback (socat bridges it
        to ``agent.sock``) instead of SLiRP's ``hostfwd=unix:``. Containers always use it:
        after a ``loadvm`` a ``hostfwd=unix:`` connection stalls 3-40 s on QEMU 11.1.1
        (8/8 reverts, research/70j §4), the TCP forward answers in < 0.11 s; QEMU < 10.2
        has no ``hostfwd=unix:`` at all."""
        image = self._image(spec)
        argv = [
            "qemu-system-m68k" if image else self.settings.qemu_m68k_bin,
            "-name",
            self.name,
            "-M",
            "q800,audiodev=snd0",
            "-m",
            str(int(spec.get("memory_mb", 128))),
            "-g",
            str(spec.get("graphics") or "640x480x8"),
            "-bios",
            self.rom_path(spec),
            # PRAM: qcow2 so savevm works (32-bit addressing lives here, 70b §3.4)
            "-drive",
            f"file={spec['pram']},format=qcow2,if=mtd",
            # onboard ESP SCSI: HD at ID 0 (the install/golden ID), CD at ID 3
            "-drive",
            f"file={spec['disk']},format=qcow2,if=none,id=hd0",
            "-device",
            "scsi-hd,scsi-id=0,drive=hd0",
        ]
        cd = spec.get("cdrom")
        # The CD device always exists (empty when no medium) so insert_cd can hot-change it.
        # An empty drive must not name a format (QEMU: "A block device must be specified").
        cd_media = f"file={cd},format=raw," if cd else ""
        argv += [
            "-drive",
            f"{cd_media}media=cdrom,if=none,id=cd0,read-only=on",
            "-device",
            "scsi-cd,scsi-id=3,drive=cd0,id=cd",
        ]
        net = spec.get("net") or {"mode": "user"}
        if net.get("mode") == "tap":
            nic = f"tap,ifname={net['ifname']},script=no,downscript=no,model=dp83932"
            if net.get("mac"):
                nic += f",mac={net['mac']}"
        else:
            # onboard SONIC on SLiRP; MacTCP gets 10.0.2.15 by BOOTP. The agent is
            # reachable ONLY through the instance's unix socket (hostfwd=unix:, libslirp
            # >= 4.7). restrict=on (default): the guest cannot reach the host or any
            # network (SLiRP would otherwise connect AS the host, past every per-project
            # isolation); the hostfwd rule still works. A per-project wbc/guestfwd path is
            # future work.
            fwd = f"tcp:127.0.0.1:{AGENT_PORT}" if agent_tcp else f"unix:{self.agent_sock_path}"
            nic = f"user,model=dp83932,hostfwd={fwd}-:{AGENT_PORT}"
            if net.get("restrict", True):
                nic += ",restrict=on"
        argv += [
            "-nic",
            nic,
            # ASC (onboard) -> the per-instance host null sink when capture is on (rvmc
            # set_audio_capture writes spec.audio_sink); else silent
            "-audiodev",
            f"pipewire,id=snd0,out.name={spec['audio_sink']}"
            if spec.get("audio_sink")
            else "none,id=snd0",
            # ESCC: first -serial = channel A (modem), second = channel B (printer)
            "-serial",
            f"unix:{self.serial_path('a')},server=on,wait=off",
            "-serial",
            f"unix:{self.serial_path('b')},server=on,wait=off",
            "-display",
            f"vnc=unix:{self.vnc_path}",
            "-qmp",
            f"unix:{self.qmp_path},server=on,wait=off",
        ]
        if spec.get("tablet"):
            # classicvirtio declrom in NuBus slot C (its PrimaryInit hard-codes slot 0xC,
            # QEMU's default for the first card) + a virtio tablet: absolute pointer with no
            # guest install. Needs 32-bit addressing (PRAM), else POST hangs (70g §3).
            declrom = DECLROM_IN_IMAGE if image else self.settings.q800_declrom
            argv += ["-device", f"nubus-virtio-mmio,romfile={declrom}",
                     "-device", "virtio-tablet-device"]  # fmt: skip
        if loadvm:
            argv += ["-loadvm", loadvm]
        return argv

    # --- prerequisites ----------------------------------------------------
    def preflight(self, spec: dict | None = None) -> None:
        """Fail clearly before a boot: binary, ROM (+ checksum/sha256 pins), disk, PRAM,
        socket path length."""
        spec = spec or self.spec()
        image = self._image(spec)
        if image:
            self._preflight_image(spec)
        else:
            exe = self.settings.qemu_m68k_bin
            if not (shutil.which(exe) if "/" not in exe else os.path.exists(exe)):
                raise BackendError(
                    f"q800: '{exe}' not found — use a base with an emulator image "
                    "(hw.emulator_image_id) or set VMCTL_QEMU_M68K_BIN"
                )
            if spec.get("tablet") and not self.settings.q800_declrom:
                raise BackendError("q800: tablet needs VMCTL_Q800_DECLROM (classicvirtio declrom)")
        if (spec.get("net") or {}).get("mode") == "tap" and image:
            raise BackendError("q800: tap networking is not available in the emulator container")
        rom = self.rom_path(spec)
        if not rom or not os.path.isfile(rom):
            raise BackendError(
                "q800: Quadra ROM missing — set VMCTL_ROM_68K (host prerequisite, "
                f"never part of the base; got {rom!r})"
            )
        want_ck = (spec.get("rom_checksum") or "").upper()
        want_sha = (spec.get("rom_sha256") or "").lower()
        if want_ck or want_sha:
            data = Path(rom).read_bytes()
            if want_ck and data[:4].hex().upper() != want_ck:
                raise BackendError(
                    f"q800: ROM checksum {data[:4].hex().upper()} != required {want_ck} ({rom})"
                )
            if want_sha and hashlib.sha256(data).hexdigest() != want_sha:
                raise BackendError(f"q800: ROM sha256 mismatch for {rom}")
        for key in ("disk", "pram"):
            if not os.path.exists(spec[key]):
                raise BackendError(f"q800: {key} {spec[key]} not found")
        for p in self._sockets():
            if len(str(p)) > _SUN_PATH_MAX:
                raise BackendError(f"q800: socket path too long for AF_UNIX: {p}")

    def _preflight_image(self, spec: dict) -> None:
        """The pinned image must be on this host."""
        image = self._image(spec)
        if not image.startswith("sha256:") or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise BackendError(f"q800: emulator_image_id must be a sha256 image id, got {image!r}")
        ref = spec.get("emulator_image") or image
        try:
            p = subprocess.run(
                [*shlex.split(self.settings.docker_bin), "image", "inspect", "--format", "{{.Id}}",
                 image],
                capture_output=True, text=True, timeout=30,
            )  # fmt: skip
        except (OSError, subprocess.TimeoutExpired) as e:
            raise BackendError(f"q800: docker unavailable ({e})") from e
        if p.returncode != 0 or p.stdout.strip() != image:
            raise BackendError(
                f"q800: emulator image {ref} ({image}) is not on this host: "
                f"docker pull {ref} (or docker load -i <tar>) and check its id"
            )

    def _mounts(self, spec: dict) -> tuple[list[Path], list[Path]]:
        """(rw, ro) host paths a containerized QEMU / qemu-img needs: the instance dir,
        the writable disk + PRAM, their read-only backing chains, the ROM and the CD."""
        rw = [self.instance_dir]
        ro: list[Path] = []
        for key in ("disk", "pram"):
            img = Path(spec[key])
            if not img.resolve().is_relative_to(self.instance_dir.resolve()):
                rw.append(img)
            ro += qcow2_backing_chain(img)
        ro += [Path(v) for v in (self.rom_path(spec), spec.get("cdrom")) if v]
        if spec.get("audio_sink"):
            rw.append(pipewire_socket())  # the ASC plays into the host PipeWire daemon
        return rw, ro

    def _launch_argv(self, spec: dict, qemu_argv: list[str]) -> list[str]:
        image = self._image(spec)
        if not image:
            return [*shlex.split(self.settings.q800_launch_prefix), *qemu_argv]
        rw, ro = self._mounts(spec)
        labels = {
            "vmctl.kind": "q800",
            "vmctl.instance": self.name,
            "vmctl.instance-dir": str(self.instance_dir.resolve()),
            "vmctl.emulator-image": str(spec.get("emulator_image") or image),
        }
        env = {"XDG_RUNTIME_DIR": str(pipewire_socket().parent)} if spec.get("audio_sink") else None
        docker = docker_run_argv(
            self.settings, image, rw=rw, ro=ro, name=self.container_name, labels=labels,
            detach=True, env=env,
        )  # fmt: skip
        # socat bridges agent.sock to QEMU's in-container agent forward (build_argv
        # agent_tcp); the container's stdout/stderr go to the instance's qemu.log (docker
        # logs vanish with --rm); exec keeps QEMU as the container's pid 1
        script = (
            'log=$0 sock=$1; shift; socat UNIX-LISTEN:"$sock",fork,unlink-early '
            f'TCP:127.0.0.1:{AGENT_PORT} >>"$log" 2>&1 & exec "$@" >>"$log" 2>&1'
        )
        return [*docker, "sh", "-c", script, str(self.log_path), str(self.agent_sock_path),
                *qemu_argv]  # fmt: skip

    # --- existence & state ------------------------------------------------
    def exists(self) -> bool:
        return self.spec_path.exists()

    def _pid(self) -> int | None:
        pid = self._runtime().get("pid")
        return int(pid) if isinstance(pid, int) else None

    def is_running(self) -> bool:
        pid = self._pid()
        if pid is None:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            pass
        # guard against pid reuse: our QMP socket path is on that process's command line
        try:
            cmdline = Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return True  # no procfs: trust the signal-0 probe
        if not cmdline:
            return False  # zombie: exited, not yet reaped by its parent
        return str(self.qmp_path).encode() in cmdline

    def state(self) -> str:
        if not self.exists():
            return "undefined"
        if not self.is_running():
            return "shut off"
        try:
            st = self.qmp("query-status").get("status", "running")
        except BackendError:
            return "running"
        return "paused" if st == "paused" else "running"

    # --- QMP --------------------------------------------------------------
    def qmp(
        self,
        command: str,
        arguments: dict | None = None,
        *,
        timeout: float = 30.0,
        fds: list[int] | None = None,
    ) -> Any:
        """One QMP command on the instance's monitor; returns ``return``. Serialized per
        instance (QEMU serves one QMP client at a time). ``fds`` are passed along with
        the command (SCM_RIGHTS), e.g. for ``add-fd``."""
        return self.qmp_session([(command, arguments, fds)], timeout=timeout)[0]

    def qmp_session(
        self, steps: list[tuple[str, dict | None, list[int] | None]], *, timeout: float = 30.0
    ) -> list[Any]:
        """Several QMP commands on ONE monitor connection (``add-fd`` + its consumer must
        share it: QEMU drops an fd set nobody uses when the monitor that added it
        disconnects). Raises on the first error."""
        out: list[Any] = []
        with _lock(self.instance_dir, "qmp"):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect(str(self.qmp_path))
            except OSError as e:
                raise BackendError(f"q800 QMP unreachable ({self.qmp_path}): {e}") from e
            with s, s.makefile("rwb") as f:

                def _send(obj: dict, with_fds: list[int] | None = None) -> None:
                    data = json.dumps(obj).encode() + b"\n"
                    if with_fds:
                        socket.send_fds(s, [data], with_fds)
                    else:
                        f.write(data)
                        f.flush()

                def _reply() -> dict:
                    while True:
                        line = f.readline()
                        if not line:
                            raise BackendError("q800 QMP closed the connection")
                        msg = json.loads(line)
                        if "return" in msg or "error" in msg:
                            return msg

                command = "qmp_capabilities"
                try:
                    f.readline()  # greeting
                    _send({"execute": command})
                    _reply()
                    for command, arguments, fds in steps:
                        cmd: dict = {"execute": command}
                        if arguments:
                            cmd["arguments"] = arguments
                        _send(cmd, fds)
                        msg = _reply()
                        if "error" in msg:
                            err = msg["error"]
                            raise BackendError(f"q800 QMP {command}: {err.get('desc', err)}")
                        out.append(msg["return"])
                except (OSError, ValueError) as e:
                    raise BackendError(f"q800 QMP {command} failed: {e}") from e
        return out

    def hmp(self, line: str, *, timeout: float = 120.0) -> str:
        """An HMP command through QMP (savevm/loadvm/delvm/info snapshots)."""
        out = self.qmp("human-monitor-command", {"command-line": line}, timeout=timeout)
        return str(out or "")

    # --- lifecycle --------------------------------------------------------
    def start(self, *, loadvm: str = "") -> None:
        # one lifecycle transition at a time per instance (two racing starts would unlink
        # each other's sockets and lose track of the QEMU that won the disk lock)
        with _lock(self.instance_dir, "life"):
            self._start(loadvm=loadvm)

    def _start(self, *, loadvm: str = "") -> None:
        if self.is_running():
            return
        spec = self.spec()
        self.preflight(spec)
        for p in (*self._sockets(), self.agent_seen_path):
            p.unlink(missing_ok=True)
        qemu_argv = self.build_argv(spec, loadvm=loadvm, agent_tcp=bool(self._image(spec)))
        argv = self._launch_argv(spec, qemu_argv)
        image = self._image(spec)
        with open(self.log_path, "ab") as log:
            log.write(f"\n--- start {time.strftime('%Y-%m-%dT%H:%M:%S')}\n".encode())
        proc: subprocess.Popen | None = None
        if image:
            # the docker daemon owns the container: a controller restart leaves it running
            self._remove_container(self.container_name)  # a leftover, or still being --rm'ed
            run = subprocess.run(argv, capture_output=True, text=True, timeout=120)
            if run.returncode != 0:
                raise BackendError(f"q800 docker run failed: {run.stderr.strip()[-600:]}")
            pid = self._container_pid()
            if not pid:
                raise BackendError(f"q800 QEMU exited at once: {self._log_tail()}")
            rt = {"pid": pid, "container": self.container_name, "image": image, "argv": argv}
        else:
            with open(self.log_path, "ab") as log:
                # Own session: a controller restart must not take the guest with it. On a
                # systemd --user controller also set VMCTL_Q800_LAUNCH_PREFIX to
                # "systemd-run --user --scope --quiet --" (else the unit's cgroup kill
                # reaps QEMU on every rvmc restart).
                proc = subprocess.Popen(
                    argv, stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                    start_new_session=True,
                )  # fmt: skip
            rt = {"pid": proc.pid, "argv": argv}
        # Atomic: an empty runtime.json after a power cut reads as "not running" and the
        # next start() launches a second QEMU against the same disk.
        write_text_atomic(self.runtime_path, json.dumps(rt))
        # QEMU creates the QMP socket before it parses the drives, so the socket file alone
        # proves nothing: wait until the monitor ANSWERS while the process is alive.
        deadline = time.time() + 20
        while time.time() < deadline:
            if (proc.poll() is not None) if proc else not self.is_running():
                self.runtime_path.unlink(missing_ok=True)
                raise BackendError(f"q800 QEMU exited: {self._log_tail()}")
            if self.qmp_path.exists():
                with contextlib.suppress(BackendError):
                    self.qmp("query-status", timeout=2)
                    return
            time.sleep(0.2)
        self.stop()
        raise BackendError(f"q800 QEMU monitor did not answer in 20 s: {self._log_tail()}")

    def _docker(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            [*shlex.split(self.settings.docker_bin), *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def _remove_container(self, name: str) -> None:
        """``docker rm -f``, then wait until the name is free: a container whose QEMU just
        exited is removed by ``--rm`` asynchronously, and a ``docker run`` reusing the name
        in that window fails with "Conflict" (seen in a boot loop after a clean shut-down)."""
        deadline = time.time() + 20
        while True:
            self._docker("rm", "-f", name)
            if self._docker("inspect", "--format", "{{.Id}}", name).returncode != 0:
                return
            if time.time() > deadline:
                raise BackendError(f"q800: container {name} is still being removed")
            time.sleep(0.2)

    def _container_pid(self) -> int:
        """Host pid of the container's QEMU (0: gone). Recorded once at start, so
        ``is_running`` stays a cheap /proc check instead of a docker round-trip."""
        p = self._docker("inspect", "--format", "{{.State.Pid}}", self.container_name)
        try:
            return int(p.stdout.strip()) if p.returncode == 0 else 0
        except ValueError:
            return 0

    def _log_tail(self, n: int = 600) -> str:
        try:
            return self.log_path.read_text(errors="replace")[-n:].strip()
        except OSError:
            return ""

    def _wait_exit(self, timeout: float) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self.is_running():
                return True
            time.sleep(0.1)
        return not self.is_running()

    def stop(self) -> None:
        with _lock(self.instance_dir, "life"):
            self._stop()

    def _stop(self) -> None:
        """Hard power-off (QMP quit, then SIGTERM/SIGKILL the process group). Idempotent."""
        pid = self._pid()
        container = self._runtime().get("container")
        if pid is not None and self.is_running():
            with contextlib.suppress(BackendError):
                self.qmp("quit", timeout=5)
            if container and not self._wait_exit(5):
                self._remove_container(str(container))
            elif not container and not self._wait_exit(5):
                for sig in (signal.SIGTERM, signal.SIGKILL):
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        pgid = os.getpgid(pid)
                        # never signal our own group (a QEMU not started in its own session)
                        if pgid == os.getpgrp():
                            os.kill(pid, sig)
                        else:
                            os.killpg(pgid, sig)
                    if self._wait_exit(5):
                        break
            # reap if it was our child (the exiting process can still be between
            # releasing its memory and becoming a zombie, so poll briefly)
            for _ in range(20):
                try:
                    if os.waitpid(pid, os.WNOHANG)[0]:
                        break
                except ChildProcessError:
                    break
                time.sleep(0.05)
        if container:  # --rm removes it once QEMU exits; make sure under any path
            with contextlib.suppress(OSError, subprocess.TimeoutExpired, BackendError):
                self._remove_container(str(container))
        self.runtime_path.unlink(missing_ok=True)

    def shutdown(self) -> None:
        """VMBackend shut-down: :meth:`shutdown_clean` (agent -> power key -> hard stop)."""
        self.shutdown_clean()

    def shutdown_clean(self, *, step_timeout: float = SHUTDOWN_STEP_S) -> str:
        """Clean System 7 shut-down: a ladder of steps, each followed by a wait (up to
        ``step_timeout``) for QEMU to exit; the first step that ends the session names the result.

        1. ``agent``: the agent's ``shutdown`` tool (Finder "Shut Down" Apple event: every app is
           asked to quit), VA1 TCP, then serial once the agent is known up;
        2. ``cmd-q``: Cmd-Q to the front application, repeated while the front process changes
           (several apps may be open), then the Finder's Shut Down again. A Director projector
           in front ignores the Finder's request (lab host 2026-10-06) but may quit on Cmd-Q;
        3. ``power-key``: ADB power key + Return (no agent needed; VA1 has no force-shutdown tool);
        4. ``hard-stop``.

        Returns the step name, or ``not-running``; also appended to the instance's qemu.log."""
        with _lock(self.instance_dir, "life"):
            if not self.is_running():
                return "not-running"
            steps = (
                ("agent", self._agent_shutdown),
                ("cmd-q", self._quit_front_apps),
                ("power-key", self._power_key),
            )
            how = "hard-stop"
            for name, act in steps:
                with contextlib.suppress(BackendError):
                    act()
                if self._wait_exit(step_timeout):
                    how = name
                    break
            self._stop()  # removes the runtime record (+ the container, if --rm has not yet)
            with contextlib.suppress(OSError), open(self.log_path, "a") as log:
                log.write(f"--- shutdown {time.strftime('%Y-%m-%dT%H:%M:%S')}: {how}\n")
            return how

    def _agent_shutdown(self) -> None:
        self.agent_call("shutdown", timeout=10)

    def _power_key(self) -> None:
        self.send_key(["KEY_POWER"])
        time.sleep(1.5)
        self.send_key(["KEY_ENTER"])

    def _front_process(self) -> str | None:
        """Name of the front process per the agent (None: agent unreachable / unknown)."""
        try:
            res = self.agent_call("list_processes", timeout=10, idempotent=True).payload
        except BackendError:
            return None
        procs = res if isinstance(res, list) else []
        return next((str(p.get("name")) for p in procs if isinstance(p, dict) and p.get("front") == "1"),
                    None)  # fmt: skip

    def _quit_front_apps(self, rounds: int = SHUTDOWN_CMDQ_ROUNDS) -> None:
        """Cmd-Q to the front app while it is not the Finder and the front keeps changing (one
        app quits, the next comes forward), then the Finder's Shut Down again. Without an agent
        answer: one Cmd-Q through QMP."""
        last = ""
        for _ in range(rounds):
            front = self._front_process()
            if front is None:
                self.send_key(["KEY_LEFTMETA", "KEY_Q"])
                time.sleep(SHUTDOWN_CMDQ_WAIT_S)
                break
            if front == "Finder" or front == last:
                break
            try:
                self.agent_call("send_keys", {"keys": "{cmd}q"}, timeout=10)
            except BackendError:
                self.send_key(["KEY_LEFTMETA", "KEY_Q"])
            last = front
            time.sleep(SHUTDOWN_CMDQ_WAIT_S)
        self._agent_shutdown()

    def reboot(self) -> None:
        """Graceful: the agent's ``restart`` tool (Finder Restart). Fallback: power cycle."""
        if self.is_running():
            try:
                self.agent_call("restart", timeout=10)
                return
            except BackendError:
                pass
        self.reset()

    def reset(self) -> None:
        """Hard power cycle. NOT QMP system_reset: on QEMU 10.0.13 q800 that leaves a
        white screen and no boot (measured 2026-10-05)."""
        self.stop()
        self.start()

    # --- settings ---------------------------------------------------------
    def get_settings(self) -> dict:
        spec = self.spec()
        return {
            "memory_mb": int(spec.get("memory_mb", 128)),
            "vcpus": 1,
            "autostart": False,
            "state": self.state(),
            "persistent": True,
        }

    def set_settings(
        self,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        autostart: bool | None = None,
        audio_sink: str | None = None,
    ) -> None:
        if audio_sink is not None:
            if "," in audio_sink:  # it lands in a QEMU option string
                raise ValueError(f"q800 audio_sink must not contain ',': {audio_sink!r}")
            if audio_sink and "pipewire" not in self.audio_drivers():
                raise BackendError(
                    "q800: this emulator has no pipewire audiodev (needs qemu-m68k "
                    ">= 11.1.1-zkm2); re-pin the instance/base emulator image first"
                )
            self._update_spec(audio_sink=audio_sink)  # '' = silent; next start
        if memory_mb is not None:
            if not 8 <= int(memory_mb) <= 1024:  # the q800 board takes 8 MB .. 1 GB
                raise ValueError(f"q800 memory_mb must be 8..1024, got {memory_mb}")
            self._update_spec(memory_mb=int(memory_mb))  # next start

    def audio_drivers(self) -> list[str]:
        """Audiodev drivers the instance's QEMU (image or host binary) was built with."""
        spec = self.spec()
        image = self._image(spec)
        cmd = ["qemu-system-m68k" if image else self.settings.qemu_m68k_bin, "-audiodev", "help"]
        if image:
            cmd = [*docker_run_argv(self.settings, image), *cmd]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if p.returncode != 0:
            raise BackendError(f"q800: '-audiodev help' failed: {p.stderr.strip()[-300:]}")
        return [ln.strip() for ln in p.stdout.splitlines()[1:] if ln.strip()]

    def tap_interface(self) -> str | None:
        net = (self.spec().get("net") or {}) if self.exists() else {}
        return net.get("ifname") if net.get("mode") == "tap" else None

    # --- definition -------------------------------------------------------
    def define(self, xml_path: str) -> None:
        """Store the instance definition. ``xml_path`` is the JSON written by
        :func:`clone_q800` (the q800 analogue of a domain XML)."""
        spec = json.loads(Path(xml_path).read_text())
        if spec.get("kind") != "q800":
            raise BackendError(f"{xml_path}: not a q800 instance definition")
        for key in ("disk", "pram"):
            if not spec.get(key):
                raise BackendError(f"{xml_path}: missing {key!r}")
        self._write_spec(spec)

    def undefine(self) -> None:
        """Remove the definition and the per-instance dir (PRAM overlay, sockets, log).
        The disk overlay belongs to the caller (like libvirt's undefine)."""
        if self.is_running():
            self.stop()
        shutil.rmtree(self.instance_dir, ignore_errors=True)

    def dumpxml(self, *args: Any, **kw: Any) -> str:
        raise BackendError("q800 is a process backend: there is no libvirt domain XML")

    # --- snapshots (internal qcow2: disk + PRAM, with RAM when live) -----
    def _check_snap(self, name: str) -> str:
        if not _SNAP_NAME.fullmatch(checked_snapshot_name(name)):
            raise BackendError(f"invalid snapshot name {name!r} (allowed: A-Z a-z 0-9 . _ -)")
        return name

    def _qemu_img(self, *args: str) -> str:
        spec = self.spec()
        image = self._image(spec)
        cmd = [self.settings.qemu_img_bin, *args]
        if image:  # the qemu-img of the golden's own emulator image
            rw, ro = self._mounts(spec)
            cmd = [*docker_run_argv(self.settings, image, rw=rw, ro=ro), "qemu-img", *args]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if p.returncode != 0:
            raise BackendError(f"qemu-img {args[0]} failed: {p.stderr.strip()}")
        return p.stdout

    @staticmethod
    def _parse_snapshots(text: str) -> dict[str, int]:
        """`info snapshots` / `qemu-img snapshot -l` table -> {tag: vm_state_bytes}."""
        out: dict[str, int] = {}
        units = {"B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40}
        for line in text.splitlines():
            parts = line.split()
            # ID TAG VM_SIZE [UNIT] DATE TIME VM_CLOCK [ICOUNT]; `info snapshots` may show '--' ids
            if len(parts) < 4 or not (parts[0].isdigit() or parts[0] == "--"):
                continue
            size, unit = parts[2], parts[3] if parts[3] in units else "B"
            try:
                out[parts[1]] = int(float(size) * units[unit])
            except ValueError:
                out[parts[1]] = 0
        return out

    def _image_snapshots(self) -> dict[str, dict[str, int]]:
        spec = self.spec()
        return {
            img: self._parse_snapshots(self._qemu_img("snapshot", "-l", img))
            for img in (spec["disk"], spec["pram"])
        }

    def _snapshots(self) -> dict[str, int]:
        """{tag: vm-state bytes}. QEMU stores the RAM state in the FIRST writable qcow2
        (the PRAM, -drive order), so offline the size is the max over both images."""
        if self.is_running():
            return self._parse_snapshots(self.hmp("info snapshots"))
        per_img = list(self._image_snapshots().values())
        disk = per_img[0]
        return {t: max(sz, *(o.get(t, 0) for o in per_img[1:])) for t, sz in disk.items()}

    def snapshot_list(self) -> list[str]:
        if not self.exists():
            return []
        return sorted(self._snapshots())

    def _hmp_ok(self, line: str) -> None:
        out = self.hmp(line).strip()
        if out:  # HMP prints nothing on success
            raise BackendError(f"q800 {line.split()[0]}: {out}")

    def snapshot_create(self, name: str, *, memory: bool = True) -> None:
        with _lock(self.instance_dir, "life"):  # disk + PRAM in one transition (no racing start)
            self._snapshot_create(name, memory=memory)

    def _snapshot_create(self, name: str, *, memory: bool = True) -> None:
        """Live: ``savevm`` (disk + PRAM + RAM, ~0.4 s). Stopped: disk + PRAM only."""
        name = self._check_snap(name)
        if self.is_running():
            if not memory:
                raise BackendError(
                    "q800: a live snapshot always includes RAM (savevm); stop the instance "
                    "for a disk-only snapshot"
                )
            if name in self._snapshots():
                self._hmp_ok(f"delvm {name}")  # overwrite semantics
            # hold the agent lock (no host call can start) and let the agent finish its
            # last connection before the RAM state is captured
            with _lock(self.instance_dir, "agent"):
                last = _LAST_AGENT_CALL.get(str(self.instance_dir), 0.0)
                time.sleep(max(0.0, SNAPSHOT_QUIESCE_S - (time.monotonic() - last)))
                self._hmp_ok(f"savevm {name}")
            return
        spec = self.spec()
        for img in (spec["disk"], spec["pram"]):
            if name in self._parse_snapshots(self._qemu_img("snapshot", "-l", img)):
                self._qemu_img("snapshot", "-d", name, img)
            self._qemu_img("snapshot", "-c", name, img)

    def snapshot_revert(self, name: str) -> None:
        """Running: ``loadvm``. Stopped: a snapshot with RAM boots straight into it
        (``-loadvm``, the VM ends up running, like libvirt); a disk-only one is applied
        to disk + PRAM and the instance stays off."""
        name = self._check_snap(name)
        # one lifecycle transition: no start() may slip in between applying disk and PRAM.
        # The restored guest may predate its agent (snapshot taken during POST): the serial
        # lane closes again until the agent answers over VA1.
        with _lock(self.instance_dir, "life"):
            self.agent_seen_path.unlink(missing_ok=True)
            self._snapshot_revert(name)

    def _snapshot_revert(self, name: str) -> None:
        snaps = self._snapshots()
        if name not in snaps:
            raise BackendError(f"snapshot {name!r} not found")
        if snaps[name] > 0:  # has RAM state
            if self.is_running():
                self._hmp_ok(f"loadvm {name}")
            else:
                self.start(loadvm=name)
            return
        # disk-only (taken while stopped): QEMU refuses loadvm, apply offline; a running
        # instance is power-cycled around it and comes back running.
        was_running = self.is_running()
        if was_running:
            self.stop()
        spec = self.spec()
        for img in (spec["disk"], spec["pram"]):
            self._qemu_img("snapshot", "-a", name, img)
        if was_running:
            self.start()

    def snapshot_delete(self, name: str) -> None:
        name = self._check_snap(name)
        if name not in self._snapshots():
            raise BackendError(f"snapshot {name!r} not found")
        if self.is_running():
            self._hmp_ok(f"delvm {name}")
            return
        for img, snaps in self._image_snapshots().items():
            if name in snaps:  # only skip an image that really lacks it
                self._qemu_img("snapshot", "-d", name, img)

    # --- screen + input ---------------------------------------------------
    def screenshot(self, screen: int = 0) -> bytes:
        """PNG via QMP screendump (QEMU >= 7.1 writes PNG directly)."""
        out = self.instance_dir / f"shot-{uuid.uuid4().hex[:8]}.png"
        try:
            self.qmp("screendump", {"filename": str(out), "format": "png"})
            return out.read_bytes()
        finally:
            out.unlink(missing_ok=True)

    def vnc_endpoint(self) -> tuple[str, int | str] | None:
        """``("unix_socket", <path>)``: QEMU's VNC listens on a unix socket in the instance
        dir (the container has no network). websockify's TokenFile target syntax for a
        unix socket is exactly ``unix_socket:<path>``."""
        if not self.is_running():
            return None
        return ("unix_socket", str(self.vnc_path))

    def send_key(self, keys: list[str]) -> None:
        if isinstance(keys, str):
            keys = [keys]
        self.qmp("send-key", {"keys": [{"type": "qcode", "data": qcode(k)} for k in keys]})

    def input_events(self, events: list[dict]) -> None:
        """Raw QMP input-send-event (relative ADB mouse / buttons)."""
        self.qmp("input-send-event", {"events": events})

    # --- CD ---------------------------------------------------------------
    def insert_cd(self, iso_path: str) -> None:
        """Persist the medium (next boot) and hot-change it when running. System 7 loads
        an APM CD's own driver at BOOT (70b §3.3), so a hot-inserted disc may need a
        restart before it mounts."""
        spec = self._update_spec(cdrom=str(iso_path))
        if not self.is_running():
            return
        if not self._image(spec):
            self.qmp(
                "blockdev-change-medium",
                {"id": "cd", "filename": str(iso_path), "format": "raw",
                 "read-only-mode": "read-only"},
            )  # fmt: skip
            return
        # containerized QEMU cannot see a path that was not mounted at start: hand it an
        # open read-only fd instead (QMP add-fd + /dev/fdset/N), then drop the fd set so
        # QEMU closes it together with the medium
        # fd set id = a fresh one per insert; add-fd, the medium change and remove-fd share
        # one monitor connection (an unused fd set dies with the connection that added it)
        fdset = int(time.time() * 1000) % 1_000_000 + 1
        fd = os.open(iso_path, os.O_RDONLY)
        try:
            self.qmp_session([
                ("add-fd", {"fdset-id": fdset}, [fd]),
                ("blockdev-change-medium", {"id": "cd", "filename": f"/dev/fdset/{fdset}",
                                            "format": "raw", "read-only-mode": "read-only"}, None),
                ("remove-fd", {"fdset-id": fdset}, None),
            ])  # fmt: skip
        finally:
            os.close(fd)

    def eject_cd(self) -> None:
        self._update_spec(cdrom=None)
        if self.is_running():
            self.qmp("eject", {"id": "cd", "force": True})

    # --- guest agent (rvmc-agent-68k) ------------------------------------
    def agent_endpoint(self) -> tuple[str, int | str] | None:
        """The agent's VA1 network lane: ``("unix_socket", <path>)`` = the SLiRP hostfwd socket in
        the instance dir; under tap the guest's static (BOOTP-reserved) ``(ip, 9009)``."""
        if not self.is_running():
            return None
        net = self.spec().get("net") or {}
        if net.get("mode") == "tap":
            return (net["ip"], AGENT_PORT) if net.get("ip") else None
        return ("unix_socket", str(self.agent_sock_path))

    def guest_ip(self) -> str | None:
        net = (self.spec().get("net") or {}) if self.exists() else {}
        return net.get("ip") if net.get("mode") == "tap" else None

    # The ESCC lanes stay closed until the agent is known to be running in this boot. Bytes
    # written to either SCC channel while the ROM is in POST put the Quadra ROM into its
    # serial test manager: the boot stops on a white screen, interrupts masked (research/70h
    # §0 2a: a ping line on A+B every 50 ms from QEMU start hung 60/60 boots; no serial byte
    # before the agent answered: 120/120 up). rvmc's guest_ping falls back to serial, so the
    # gate has to live here.
    @property
    def agent_seen_path(self) -> Path:
        return self.instance_dir / "agent-seen"

    def _mark_agent_seen(self) -> None:
        self.agent_seen_path.touch()

    def wait_serial_hello(self, timeout: float = 120.0) -> bool:
        """Wait for network readiness before enabling ESCC input in this boot.

        VA1 has no unsolicited serial hello. This retained entry point now probes
        the network lane only; it returns False if network readiness is unproven.
        Serial-only cold boots need an out-of-band readiness signal before the
        ROM POST gate can safely be opened.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.agent_seen_path.exists():
                return True
            # Disable retries/grace for this readiness probe to honour its deadline.
            try:
                with self._agent_session(("http",)) as client:
                    client.retries = 0
                    client.grace = 0
                    client.call("ping", timeout=min(5.0, deadline - time.monotonic()))
                    self._mark_agent_seen()
                    return True
            except BackendError:
                pass
            time.sleep(min(0.2, max(0, deadline - time.monotonic())))
        return False

    def _connect_serial(self, timeout: float) -> socket.socket:
        if not self.agent_seen_path.exists():
            raise BackendError(
                "serial lane closed until the agent is up in this boot "
                "(ESCC input during ROM POST hangs a q800 boot); use the network lane first"
            )
        return UnixTransport(str(self.serial_path("b"))).connect(timeout)

    @contextlib.contextmanager
    def _agent_session(self, lanes: tuple[str, ...] = ("http", "serial")) -> Iterator[AgentClient]:
        with _lock(self.instance_dir, "agent"):
            try:
                connectors = []
                if "http" in lanes or "tcp" in lanes:
                    ep = self.agent_endpoint()
                    if not ep:
                        if self.runtime_path.exists():
                            raise BackendError(
                                f"q800 QEMU exited unexpectedly: {self._log_tail(300)}"
                            )
                        raise AgentUnreachable(
                            "q800 agent: instance not running", reached_guest=False
                        )
                    transport = (
                        UnixTransport(str(ep[1]))
                        if ep[0] == "unix_socket"
                        else TCPTransport(ep[0], int(ep[1]))
                    )
                    connectors.append(transport.connect)
                if "serial" in lanes:
                    connectors.append(self._connect_serial)
                with agent_session(connectors) as client:
                    yield client
            finally:  # the settle before savevm counts from the END of the last call
                _LAST_AGENT_CALL[str(self.instance_dir)] = time.monotonic()

    def agent_call(
        self,
        tool: str,
        arguments: dict | None = None,
        *,
        timeout: float = 20.0,
        lanes: tuple[str, ...] = ("http", "serial"),
        idempotent: bool = False,
    ) -> Reply:
        """Return VA1 Reply (decoded kv, rows or raw payload); errors raise BackendError.

        The retained ``http`` lane name selects VA1 TCP through SLiRP, never HTTP.
        ``tcp`` selects the same lane. Serial uses the ESCC .B socket after the boot
        gate opens. ``idempotent`` is retained but unnecessary: VA1 retries preserve
        the request ID, including reconnects across lanes, for every tool.
        """
        with self._agent_session(lanes) as client:
            client.hello(timeout=timeout)
            self._mark_agent_seen()
            return client.call(tool, arguments, timeout=timeout)

    def guest_ping(
        self, timeout: float = 5.0, *, lanes: tuple[str, ...] = ("http", "serial")
    ) -> bool:
        """Return True on a VA1 ping Reply, False on tool or transport failure."""
        try:
            self.agent_call("ping", timeout=timeout, lanes=lanes, idempotent=True)
            return True
        except BackendError:
            return False

    def guest_exec(self, path, args=None, *, timeout: float = 15.0):
        raise BackendError(
            "System 7 has no shell: open apps/documents with the agent's run_app {path}"
        )

    def guest_write_file(self, guest_path: str, data: bytes) -> None:
        """Write raw VA1 chunks sized by hello.max_frame; truncate even empty files."""
        with self._agent_session() as client:
            client.hello(timeout=60)
            self._mark_agent_seen()
            client.write_file(guest_path, data, timeout=60)

    def guest_read_file(self, guest_path: str) -> bytes:
        """Return raw file bytes, validating VA1 size, offsets and EOF across chunks."""
        with self._agent_session() as client:
            client.hello()
            self._mark_agent_seen()
            return client.read_file(guest_path)

    # --- network ----------------------------------------------------------
    def net_info(self) -> dict:
        net = (self.spec().get("net") or {}) if self.exists() else {}
        if net.get("mode") == "tap":
            return {"subnet": None, "interfaces": [{"ip": net.get("ip")}] if net.get("ip") else []}
        return {"subnet": "10.0.2.0/24", "interfaces": [{"ip": "10.0.2.15", "nat": "slirp"}]}
