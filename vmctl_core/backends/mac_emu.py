"""Classic-Mac emulator VMBackends: SheepShaver (PPC) + Basilisk II (68k).

Implements the ``VMBackend`` contract over an emulator *process group* instead of a
libvirt domain, per research/52. These are NOT libvirt: SheepShaver/Basilisk are
ordinary SDL2 apps, so a single instance is a supervised trio of processes on a
private headless X display::

    SheepShaver (SDL2, screen=win/W/H, hardware cursor)
       -> renders into  Xvfb :N            (virtual framebuffer, in RAM)
       -> scraped by     x11vnc :590X       (-localhost -forever -shared)
       -> raw TCP        websockify (the ONE shared proxy)  <- UNCHANGED (research/03)
       -> wss            noVNC in our page                  <- UNCHANGED

Everything downstream of x11vnc is byte-identical to the QEMU path — we only swap
the VNC *source*. The whole point (research/52 headline): SheepShaver's SDL2
backend draws a hardware cursor synced to the Mac OS cursor at the host's absolute
window-relative position, so noVNC's absolute pointer maps 1:1 with no offset — the
exact failure mode QEMU's relative ``usb-mouse`` has over RFB.

Two backends, one wrapper (they share the ``cebix/macemu`` tree, prefs grammar,
SDL2 mouse and process model):

* :class:`SheepShaverBackend` — PPC, Mac OS 8.1 - 9.0.4 (hard MMU ceiling 9.0.4),
  NewWorld PPC ROM.
* :class:`BasiliskIIBackend`  — 68k, System 7 - Mac OS 8.1, a 68k Quadra ROM.
  A thin subclass: same wrapper, different binary + ROM + OS ceiling.

Deliberate limitations vs libvirt (research/52 §6):
* No live save-state. ``supports_live_snapshot = False``: snapshots are *cold*
  disk-image copies of the ``.dsk`` volume, revert = re-copy + restart.
* No in-guest agent. ``guest_*`` all raise / return falsey — the MacOS9Module is
  already agentless (host-only) for this tier, so this matches.

CANNOT be exercised here without a real binary + a legally-sourced Mac ROM
(research/18). The code is validated structurally; the make-or-break items
(1:1 mouse through noVNC, extfs RW, boot with a ROM) must be verified on-box.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import time
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

from .base import BackendError


# --- host tool + emulator configuration (env-overridable, NEVER hardcoded) -------
class MacEmuSettings(BaseSettings):
    """Host prerequisites for the classic-Mac backends (research/52 §8).

    Binaries and ROMs are host prerequisites, resolved from the environment (or a
    config file that populates these), never baked into a base image or a published
    catalog (ROM legality — research/18). Every field is overridable via the
    ``VMCTL_`` env prefix, e.g. ``VMCTL_SHEEPSHAVER_BIN`` / ``VMCTL_NEWWORLD_ROM``.
    """

    model_config = SettingsConfigDict(env_prefix="VMCTL_", extra="ignore")

    # emulator binaries (from the cebix/macemu or tycho/macemu SDL2 build)
    sheepshaver_bin: str = "SheepShaver"
    basilisk_bin: str = "BasiliskII"

    # Apple-copyright Mac ROMs — host prereqs, extracted from an owned Mac only
    # (research/18). Empty => the backend refuses to start with a clear error.
    newworld_rom: str = ""  # NewWorld PPC ROM for SheepShaver
    rom_68k: str = ""  # 68k Quadra/Performa ROM (1 MB) for Basilisk II

    # headless X stack (research/52 §5)
    xvfb_bin: str = "Xvfb"
    x11vnc_bin: str = "x11vnc"
    xdotool_bin: str = "xdotool"
    xwd_bin: str = "xwd"
    convert_bin: str = "convert"  # ImageMagick: xwd -> png

    # where per-instance runtime dirs (prefs, cloned .dsk, snapshots) live
    state_dir: Path = Path("/var/lib/vmctl/mac")

    vnc_host: str = "127.0.0.1"


# libvirt/linux KEY_* input names -> xdotool keysyms. Unmapped KEY_* fall back to
# the suffix lower-cased (KEY_A -> a, KEY_5 -> 5), which xdotool accepts directly.
_XDOTOOL_KEYS = {
    "KEY_ESC": "Escape",
    "KEY_ENTER": "Return",
    "KEY_TAB": "Tab",
    "KEY_SPACE": "space",
    "KEY_BACKSPACE": "BackSpace",
    "KEY_DELETE": "Delete",
    "KEY_UP": "Up",
    "KEY_DOWN": "Down",
    "KEY_LEFT": "Left",
    "KEY_RIGHT": "Right",
    "KEY_HOME": "Home",
    "KEY_END": "End",
    "KEY_PAGEUP": "Prior",
    "KEY_PAGEDOWN": "Next",
    "KEY_INSERT": "Insert",
    "KEY_LEFTCTRL": "ctrl",
    "KEY_RIGHTCTRL": "ctrl",
    "KEY_LEFTALT": "alt",
    "KEY_RIGHTALT": "alt",
    "KEY_LEFTSHIFT": "shift",
    "KEY_RIGHTSHIFT": "shift",
    "KEY_LEFTMETA": "super",
    "KEY_RIGHTMETA": "super",
    **{f"KEY_F{i}": f"F{i}" for i in range(1, 13)},
}


def _xdotool_key(name: str) -> str:
    name = str(name).strip()
    if name in _XDOTOOL_KEYS:
        return _XDOTOOL_KEYS[name]
    if name.upper().startswith("KEY_"):
        return name[4:].lower()
    return name


def render_prefs(prefs: dict) -> str:
    """Render a SheepShaver/Basilisk prefs file (E-Maculation grammar): one
    ``key value`` per line, booleans as ``true``/``false``. Pure — unit-testable
    with no binary present (research/52 §4)."""
    lines: list[str] = []
    for key, val in prefs.items():
        if val is None:
            continue
        if isinstance(val, bool):
            val = "true" if val else "false"
        lines.append(f"{key} {val}")
    return "\n".join(lines) + "\n"


class _MacEmuBackend:
    """Shared SheepShaver/Basilisk wrapper — a VMBackend over a process group.

    Subclasses set :attr:`emulator_bin`, :attr:`rom_path` and :attr:`os_ceiling`.
    One instance == one supervised (Xvfb, emulator, x11vnc) trio, the direct
    analogue of one libvirt domain.
    """

    # classic-Mac emulators have no qemu-style RAM+device snapshot (research/52 §6)
    supports_live_snapshot = False
    # subclass-specific:
    emulator_bin = ""  # resolved emulator executable
    rom_path = ""  # resolved ROM path
    os_ceiling = ""  # human note, e.g. "9.0.4"

    def __init__(
        self,
        name: str,
        *,
        disk: str,
        settings: MacEmuSettings,
        instance_dir: str | Path | None = None,
        extfs_dir: str | Path | None = None,
        cdrom: str | None = None,
        screen: str = "win/1024/768",
        memory_mb: int = 256,
        display_num: int = 80,
        vnc_port: int = 5980,
        ether: str = "slirp",
        jit: bool = True,
        audio_sink: str = "",
    ) -> None:
        self.name = name
        self.settings = settings
        self.disk = str(disk)
        # per-instance runtime home (prefs, snapshots). Defaults under state_dir.
        self.instance_dir = Path(instance_dir or (settings.state_dir / f"inst-{name}"))
        # extfs = the host<->guest transfer lane; wire to work/datalink/files/
        # (research/68) so it doubles as the datalink share. None => no extfs mount.
        self.extfs_dir = Path(extfs_dir) if extfs_dir else None
        self.cdrom = str(cdrom) if cdrom else None
        self.screen = screen
        self.memory_mb = int(memory_mb)
        self.display_num = int(display_num)
        self.vnc_port = int(vnc_port)
        self.ether = ether
        self.jit = jit
        self.audio_sink = audio_sink
        # live process handles (populated by start())
        self._procs: dict[str, subprocess.Popen] = {}

    # --- paths ------------------------------------------------------------
    @property
    def prefs_path(self) -> Path:
        return self.instance_dir / "prefs"

    @property
    def nvram_path(self) -> Path:
        return self.instance_dir / "nvram"

    @property
    def snapshots_dir(self) -> Path:
        return self.instance_dir / "snapshots"

    @property
    def pidfile_path(self) -> Path:
        # Durable record of the (Xvfb, emulator, x11vnc) pids, so a *restarted*
        # controller — whose in-memory ``self._procs`` is gone — can still find,
        # reap, or refuse-to-duplicate the trio bound to this display/VNC port.
        return self.instance_dir / "pids.json"

    @property
    def display(self) -> str:
        return f":{self.display_num}"

    # --- prefs generation -------------------------------------------------
    def build_prefs(self) -> dict:
        """The load-bearing prefs (research/52 §4). ``screen=win/W/H`` (windowed
        SDL2 -> hardware-cursor abs-mouse path, NOT ``dga``); ``nogui true`` boots
        straight past the SDL prefs editor (essential headless)."""
        prefs: dict = {
            "rom": self.rom_path,
            "disk": self.disk,
            "screen": self.screen,  # win/W/H (NOT dga)
            "ramsize": self.memory_mb * 1024 * 1024,  # bytes
            "nvram": str(self.nvram_path),
            "frameskip": 0,
            "jit": self.jit,
            "nosound": False,  # SDL2 audio on (research/52 §7)
            "ether": self.ether,  # slirp user-mode NAT
            "nogui": True,  # skip SDL prefs GUI
            "bootdriver": 0,  # first bootable volume
        }
        if self.extfs_dir is not None:
            prefs["extfs"] = str(self.extfs_dir)  # host dir as a Mac volume
        if self.cdrom:
            prefs["cdrom"] = self.cdrom
        return prefs

    def write_prefs(self) -> Path:
        self.instance_dir.mkdir(parents=True, exist_ok=True)
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        if self.extfs_dir is not None:
            self.extfs_dir.mkdir(parents=True, exist_ok=True)
        self.prefs_path.write_text(render_prefs(self.build_prefs()))
        return self.prefs_path

    # --- prerequisite validation -----------------------------------------
    def _require(self, *tool_or_path: str) -> None:
        """Fail clearly (research/52: 'fail clearly if absent') when a required
        binary is not on PATH or a required file does not exist."""
        for t in tool_or_path:
            if not t:
                raise BackendError(
                    f"{type(self).__name__}: a required emulator/ROM path is "
                    "unset — set the VMCTL_* env/config (research/52 §3)."
                )
            found = shutil.which(t) if "/" not in t else (t if os.path.exists(t) else None)
            if not found:
                raise BackendError(f"{type(self).__name__}: '{t}' not found (host prereq)")

    def preflight(self) -> None:
        """Validate every host prereq for a boot. Safe to call without side effects."""
        self._require(self.emulator_bin, self.rom_path, self.disk)
        s = self.settings
        self._require(s.xvfb_bin, s.x11vnc_bin, s.xdotool_bin, s.xwd_bin, s.convert_bin)

    # --- existence & state ------------------------------------------------
    def exists(self) -> bool:
        """'Defined' == the per-instance prefs file has been written."""
        return self.prefs_path.exists()

    # --- pidfile (survives a controller restart) --------------------------
    def _read_pidfile(self) -> dict[str, int]:
        try:
            data = json.loads(self.pidfile_path.read_text())
            if not isinstance(data, dict):
                return {}
            # int() coercion must be INSIDE the guard: a hand-edited / partially-written
            # pidfile with a non-integer value would otherwise raise ValueError out of
            # is_running()/state()/stop() and wedge the instance.
            return {str(k): int(v) for k, v in data.items()}
        except (FileNotFoundError, ValueError, TypeError):
            return {}

    def _write_pidfile(self) -> None:
        pids = {key: p.pid for key, p in self._procs.items()}
        self.instance_dir.mkdir(parents=True, exist_ok=True)
        self.pidfile_path.write_text(json.dumps(pids))

    def _clear_pidfile(self) -> None:
        self.pidfile_path.unlink(missing_ok=True)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True  # exists, owned by someone else
        return True

    def _role_alive(self, key: str, pidfile: dict[str, int] | None = None) -> bool:
        """Is this trio member up — via the live Popen handle if we launched it,
        else via the persisted pidfile (restarted-controller case)."""
        p = self._procs.get(key)
        if p is not None:
            return p.poll() is None
        if pidfile is None:
            pidfile = self._read_pidfile()
        pid = pidfile.get(key)
        return pid is not None and self._pid_alive(pid)

    def _any_alive(self) -> bool:
        pidfile = self._read_pidfile()
        return any(self._role_alive(k, pidfile) for k in ("emulator", "x11vnc", "xvfb"))

    def is_running(self) -> bool:
        # The emulator == the VM. Consult the pidfile too so a restarted
        # controller (empty ``self._procs``) still sees a running instance.
        return self._role_alive("emulator")

    def state(self) -> str:
        if self.is_running():
            return "running"
        return "shut off" if self.exists() else "undefined"

    # --- lifecycle --------------------------------------------------------
    def _popen(self, key: str, argv: list[str], *, env: dict | None = None) -> None:
        # start_new_session => own process group, so stop() can killpg the trio.
        self._procs[key] = subprocess.Popen(
            argv,
            env=env,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def start(self) -> None:
        if self.is_running():
            return
        # A partial trio — Xvfb/x11vnc survivors from a crash, a failed prior
        # start, or a controller that restarted mid-life (pidfile) — would collide
        # on this display/VNC port and orphan the old handles. Reap it first so a
        # retry never duplicate-launches on top of a survivor.
        if self._any_alive():
            self.stop()
        self.preflight()
        self.write_prefs()
        s = self.settings
        w, h = self._screen_wh()
        try:
            # 1) headless X framebuffer sized to the SDL window (research/52 §5).
            self._popen("xvfb", [s.xvfb_bin, self.display, "-screen", "0", f"{w}x{h}x16"])
            self._wait_display()
            # 2) the emulator, rendering into that display; SDL2 audio -> the
            #    per-instance null sink (same sink the QEMU guests use — §7).
            env = dict(os.environ, DISPLAY=self.display)
            if self.audio_sink:
                env["SDL_AUDIODRIVER"] = env.get("SDL_AUDIODRIVER", "pulseaudio")
                env["PULSE_SINK"] = self.audio_sink
            self._popen("emulator", [self.emulator_bin, "--config", str(self.prefs_path)], env=env)
            # 3) x11vnc scrapes the display onto the port tokens.d expects.
            #    -localhost keeps the raw port private (only websockify reaches it).
            self._popen(
                "x11vnc",
                [
                    s.x11vnc_bin,
                    "-display",
                    self.display,
                    "-rfbport",
                    str(self.vnc_port),
                    "-localhost",
                    "-forever",
                    "-shared",
                    "-nopw",
                    "-quiet",
                ],
            )
        except Exception:
            # Roll back: tear down whatever already came up so no half-started
            # trio leaks on the display/port.
            self.stop()
            raise
        # Persist the pids so a restarted controller can adopt/reap the trio.
        self._write_pidfile()

    def _screen_wh(self) -> tuple[int, int]:
        # screen forms: 'win/W/H' or 'sdl/W/H'; default to 1024x768.
        parts = self.screen.split("/")
        if len(parts) == 3:
            try:
                return int(parts[1]), int(parts[2])
            except ValueError:
                pass
        return 1024, 768

    def _wait_display(self, timeout: float = 5.0) -> None:
        """Wait until Xvfb answers on the display (xdpyinfo-free: poll the X
        socket). Raises if the Xvfb process died during bring-up so ``start()``
        rolls back instead of launching the emulator against a dead display."""
        sock = f"/tmp/.X11-unix/X{self.display_num}"
        xvfb = self._procs.get("xvfb")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if xvfb is not None and xvfb.poll() is not None:
                raise BackendError(
                    f"Xvfb {self.display} exited (rc={xvfb.returncode}) during startup"
                )
            if os.path.exists(sock):
                return
            time.sleep(0.1)

    def stop(self) -> None:
        """Hard power-off: SIGTERM each process group (emulator, x11vnc, Xvfb).
        Idempotent. Operates on the live Popen handles when we launched them, else
        on the pids persisted in the pidfile (restarted-controller case)."""
        pidfile = self._read_pidfile()
        trio = ("emulator", "x11vnc", "xvfb")

        def _pid_for(key: str) -> int | None:
            p = self._procs.get(key)
            return p.pid if p is not None else pidfile.get(key)

        for key in trio:
            if not self._role_alive(key, pidfile):
                continue
            pid = _pid_for(key)
            if pid is None:
                continue
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(os.getpgid(pid), signal.SIGTERM)
        # reap; escalate to SIGKILL on stragglers
        deadline = time.time() + 5.0
        for key in trio:
            pid = _pid_for(key)
            if pid is None:
                continue
            while self._role_alive(key, pidfile) and time.time() < deadline:
                time.sleep(0.1)
            if self._role_alive(key, pidfile):
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                # Reap our own child after SIGKILL so it doesn't linger as a
                # zombie until GC drops the Popen (Codex P3).
                p = self._procs.get(key)
                if p is not None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        p.wait(timeout=2.0)
        self._procs.clear()
        self._clear_pidfile()

    def shutdown(self) -> None:
        # No ACPI / guest agent on classic Mac — a clean in-guest shutdown needs a
        # human (Special > Shut Down). Best-effort == hard stop.
        self.stop()

    def reboot(self) -> None:
        self.stop()
        self.start()

    def reset(self) -> None:
        self.reboot()

    # --- settings ---------------------------------------------------------
    def get_settings(self) -> dict:
        return {
            "memory_mb": self.memory_mb,
            "vcpus": 1,  # single-threaded emulator
            "autostart": False,
            "state": self.state(),
            "persistent": self.exists(),
        }

    def set_settings(
        self,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        autostart: bool | None = None,
    ) -> None:
        # vcpus/autostart are inert for a single-process emulator. memory takes
        # effect on next start (rewrite prefs).
        if memory_mb is not None:
            self.memory_mb = int(memory_mb)
            if self.exists():
                self.write_prefs()

    def tap_interface(self) -> str | None:
        return None  # slirp user-mode NAT: no host tap to capture

    # --- domain definition ------------------------------------------------
    def define(self, xml_path: str | None = None) -> None:
        """The classic-Mac analogue of ``virsh define`` is writing the prefs file.
        ``xml_path`` is accepted for Protocol compatibility and ignored (there is no
        libvirt XML for an emulator process)."""
        self.write_prefs()

    def undefine(self) -> None:
        if self.is_running():
            self.stop()
        with contextlib.suppress(FileNotFoundError):
            self.prefs_path.unlink()

    # --- snapshots (COLD, disk-image copies — research/52 §6) -------------
    def _snap_path(self, name: str) -> Path:
        return self.snapshots_dir / f"{name}.dsk"

    def snapshot_list(self) -> list[str]:
        if not self.snapshots_dir.exists():
            return []
        return sorted(p.stem for p in self.snapshots_dir.glob("*.dsk"))

    def snapshot_create(self, name: str, *, memory: bool = True) -> None:
        """COLD snapshot: copy the instance .dsk. ``memory`` is ignored — there is
        no live RAM state to capture (``supports_live_snapshot = False``).

        Refuses while running: the emulator holds the volume open R/W, so a live
        copy captures a torn image. Mirrors ``snapshot_revert()``, which stops
        first before touching the .dsk (research/52 §6)."""
        if self.is_running():
            raise BackendError(
                f"refusing to snapshot {name!r} while running: the emulator holds "
                "the .dsk open R/W (torn cold image) — stop the instance first"
            )
        self.snapshots_dir.mkdir(parents=True, exist_ok=True)
        self._reflink_copy(Path(self.disk), self._snap_path(name))

    def snapshot_revert(self, name: str) -> None:
        snap = self._snap_path(name)
        if not snap.exists():
            raise BackendError(f"snapshot {name!r} not found")
        was_running = self.is_running()
        if was_running:
            self.stop()
        # Copy to a same-dir temp then atomically rename over the live disk: a failed
        # or interrupted copy (ENOSPC, crash mid-cp) must never leave the instance's
        # only .dsk torn with no rollback. os.replace is atomic within a filesystem.
        disk = Path(self.disk)
        tmp = disk.with_name(f".{disk.name}.revert.tmp")
        try:
            self._reflink_copy(snap, tmp)
            os.replace(tmp, disk)
        except BaseException:
            with contextlib.suppress(FileNotFoundError):
                tmp.unlink()
            raise
        if was_running:
            self.start()

    def snapshot_delete(self, name: str) -> None:
        try:
            self._snap_path(name).unlink()
        except FileNotFoundError:
            raise BackendError(f"snapshot {name!r} not found") from None

    @staticmethod
    def _reflink_copy(src: Path, dst: Path) -> None:
        """CoW copy where the FS supports it (Btrfs/XFS), else a plain copy
        (research/52 §6: 'cp --reflink=auto')."""
        dst.parent.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                ["cp", "--reflink=auto", str(src), str(dst)],
                check=True,
                capture_output=True,
                text=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError):
            shutil.copy2(src, dst)

    # --- screen -----------------------------------------------------------
    def screenshot(self, screen: int = 0) -> bytes:
        """PNG of the Xvfb root via ``xwd | convert`` (research/52 §3). No guest
        cooperation needed."""
        self._require(self.settings.xwd_bin, self.settings.convert_bin)
        xwd = subprocess.run(
            [self.settings.xwd_bin, "-root", "-silent", "-display", self.display],
            capture_output=True,
            check=True,
        )
        png = subprocess.run(
            [self.settings.convert_bin, "xwd:-", "png:-"],
            input=xwd.stdout,
            capture_output=True,
            check=True,
        )
        return png.stdout

    def vnc_endpoint(self) -> tuple[str, int] | None:
        return (self.settings.vnc_host, self.vnc_port)

    def _xdotool(self, *args: str) -> None:
        """Run xdotool against the Xvfb display, raising on a non-zero rc so the
        programmatic lane surfaces a gone/undelivered display instead of silently
        reporting success (Codex P3)."""
        r = subprocess.run(
            [self.settings.xdotool_bin, *args],
            env=dict(os.environ, DISPLAY=self.display),
            capture_output=True,
            text=True,
            check=False,
        )
        if r.returncode != 0:
            raise BackendError(f"xdotool {args[0]} failed (rc={r.returncode}): {r.stderr.strip()}")

    def send_key(self, keys: list[str]) -> None:
        """Inject a keystroke/chord via xdotool against the Xvfb display. A list is
        a simultaneous chord (KEY_LEFTCTRL+KEY_LEFTALT+KEY_DELETE -> ctrl+alt+Delete)."""
        if isinstance(keys, str):
            keys = [keys]
        combo = "+".join(_xdotool_key(k) for k in keys)
        self._xdotool("key", "--clearmodifiers", combo)

    def move_mouse(self, x: int, y: int) -> None:
        """Absolute pointer move via xdotool (programmatic/testing lane). Live
        interactive mouse goes straight through noVNC -> x11vnc -> SDL2, which is
        the 1:1 hardware-cursor path (research/52 §5); this is for automation."""
        self._xdotool("mousemove", str(int(x)), str(int(y)))

    def click_mouse(self, button: int = 1) -> None:
        self._xdotool("click", str(int(button)))

    # --- CD (no live hotplug on classic Mac -> rewrite prefs + restart) ---
    def insert_cd(self, iso_path: str) -> None:
        self.cdrom = str(iso_path)
        if self.exists():
            self.write_prefs()
        if self.is_running():
            self.reboot()  # classic Mac re-enumerates media only at boot

    def eject_cd(self) -> None:
        self.cdrom = None
        if self.exists():
            self.write_prefs()
        if self.is_running():
            self.reboot()

    # --- guest agent (none on classic Mac — host-only MacOS9Module) -------
    def guest_ping(self, timeout: float = 5.0) -> bool:
        return False

    def guest_exec(self, path, args=None, *, timeout: float = 15.0):
        raise BackendError("classic-Mac emulator has no in-guest agent (host-only)")

    def guest_write_file(self, guest_path: str, data: bytes) -> None:
        raise BackendError(
            "no in-guest agent — use the extfs shared volume for host->guest transfer"
        )

    def guest_read_file(self, guest_path: str) -> bytes:
        raise BackendError(
            "no in-guest agent — use the extfs shared volume for guest->host transfer"
        )

    # --- network ----------------------------------------------------------
    def net_info(self) -> dict:
        return {"subnet": None, "interfaces": []}


class SheepShaverBackend(_MacEmuBackend):
    """PPC classic-Mac (Mac OS 8.1 - 9.0.4). NewWorld PPC ROM. JIT."""

    os_ceiling = "9.0.4"

    def __init__(self, name: str, **kwargs) -> None:
        settings: MacEmuSettings = kwargs["settings"]
        self.emulator_bin = settings.sheepshaver_bin
        self.rom_path = kwargs.pop("rom", None) or settings.newworld_rom
        super().__init__(name, **kwargs)


class BasiliskIIBackend(_MacEmuBackend):
    """68k classic-Mac (System 7 - Mac OS 8.1). 68k Quadra ROM. Same wrapper as
    SheepShaver, different binary + ROM (research/52 §2)."""

    os_ceiling = "8.1"

    def __init__(self, name: str, **kwargs) -> None:
        settings: MacEmuSettings = kwargs["settings"]
        self.emulator_bin = settings.basilisk_bin
        self.rom_path = kwargs.pop("rom", None) or settings.rom_68k
        super().__init__(name, **kwargs)
