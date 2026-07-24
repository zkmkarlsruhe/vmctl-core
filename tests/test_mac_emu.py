"""SheepShaver / Basilisk II VMBackend (research/52): structural validation.

A real SheepShaver needs a gated binary + a legally-sourced Mac ROM (research/18),
so these tests do NOT boot an emulator. They validate the structure that must hold
regardless: the Protocol match, catalog-driven backend selection, prefs generation,
cold-snapshot semantics, the extfs wiring, and that host prereqs fail clearly.
"""

import json
import os
import subprocess

import pytest

from vmctl_core.backends import (
    BackendError,
    BasiliskIIBackend,
    LibvirtBackend,
    MacEmuSettings,
    SheepShaverBackend,
    VMBackend,
    backend_for,
    is_mac_emu,
    render_prefs,
    resolve_backend_kind,
)
from vmctl_core.catalog import BaseImage, Hardware


def _settings(tmp_path, **kw):
    return MacEmuSettings(
        newworld_rom=str(tmp_path / "newworld.rom"),
        rom_68k=str(tmp_path / "quadra.rom"),
        state_dir=tmp_path / "state",
        **kw,
    )


def _sheep(tmp_path, **kw):
    kw.setdefault("disk", str(tmp_path / "macos9.dsk"))
    return SheepShaverBackend("inst-1", settings=_settings(tmp_path), **kw)


# --- Protocol conformance ---------------------------------------------------
def test_backends_satisfy_the_vmbackend_protocol(tmp_path):
    be = _sheep(tmp_path)
    assert isinstance(be, VMBackend)
    assert isinstance(LibvirtBackend("d"), VMBackend)


def test_interface_matches_libvirt_backend(tmp_path):
    """Every public VMBackend method LibvirtBackend exposes must exist on the mac
    backend too (so the controller's stable surface works against either)."""
    surface = [
        "exists",
        "state",
        "is_running",
        "start",
        "stop",
        "shutdown",
        "reboot",
        "reset",
        "get_settings",
        "set_settings",
        "tap_interface",
        "define",
        "undefine",
        "snapshot_list",
        "snapshot_create",
        "snapshot_revert",
        "snapshot_delete",
        "screenshot",
        "vnc_endpoint",
        "send_key",
        "insert_cd",
        "eject_cd",
        "guest_ping",
        "guest_exec",
        "guest_write_file",
        "guest_read_file",
        "net_info",
    ]
    be = _sheep(tmp_path)
    for m in surface:
        assert callable(getattr(be, m, None)), m
    assert be.name == "inst-1"


# --- catalog-driven selection ----------------------------------------------
def test_resolve_backend_kind_defaults_are_non_breaking():
    # bare base (x86) and the existing ppc mac9 (9.2.2) tier BOTH stay on libvirt
    assert resolve_backend_kind(BaseImage(id="x", path="a.qcow2", os="linux")) == "libvirt"
    ppc = BaseImage(id="mac9", path="m.qcow2", os="mac-os-9", hw=Hardware(arch="ppc"))
    assert resolve_backend_kind(ppc) == "libvirt"
    assert not is_mac_emu(ppc)


def test_resolve_backend_kind_explicit_and_inferred():
    ss = BaseImage(id="s", path="d.dsk", os="mac-os-9", hw=Hardware(backend="sheepshaver"))
    assert resolve_backend_kind(ss) == "sheepshaver" and is_mac_emu(ss)
    m68 = BaseImage(id="b", path="d.dsk", os="system-7", hw=Hardware(arch="m68k"))
    assert resolve_backend_kind(m68) == "basilisk2"


def test_resolve_backend_kind_rejects_unknown():
    bad = BaseImage(id="x", path="d.dsk", os="mac", hw=Hardware(backend="bochs"))
    with pytest.raises(ValueError):
        resolve_backend_kind(bad)


def test_backend_for_builds_each_kind(tmp_path):
    s = _settings(tmp_path)
    lib = backend_for(BaseImage(id="l", path="a.qcow2", os="linux"), "d1")
    assert isinstance(lib, LibvirtBackend)

    ssbase = BaseImage(
        id="s",
        path="d.dsk",
        os="mac-os-9",
        hw=Hardware(backend="sheepshaver", memory_mb=512, mac_screen="win/800/600"),
    )
    ss = backend_for(
        ssbase,
        "d2",
        mac_settings=s,
        disk=str(tmp_path / "d.dsk"),
        extfs_dir=str(tmp_path / "files"),
        vnc_port=5981,
        display_num=81,
    )
    assert isinstance(ss, SheepShaverBackend)
    assert ss.memory_mb == 512 and ss.screen == "win/800/600"
    assert ss.vnc_endpoint() == ("127.0.0.1", 5981)

    b2base = BaseImage(id="b", path="d.dsk", os="system-7", hw=Hardware(arch="m68k"))
    b2 = backend_for(b2base, "d3", mac_settings=s, disk=str(tmp_path / "b.dsk"))
    assert isinstance(b2, BasiliskIIBackend)


def test_backend_for_mac_requires_disk(tmp_path):
    ssbase = BaseImage(id="s", path="d.dsk", os="mac", hw=Hardware(backend="sheepshaver"))
    with pytest.raises(ValueError):
        backend_for(ssbase, "d", mac_settings=_settings(tmp_path))


# --- prefs generation -------------------------------------------------------
def test_render_prefs_grammar():
    out = render_prefs(
        {
            "rom": "/r.rom",
            "jit": True,
            "nosound": False,
            "ramsize": 268435456,
            "screen": "win/1024/768",
            "skip": None,
        }
    )
    lines = out.splitlines()
    assert "rom /r.rom" in lines
    assert "jit true" in lines
    assert "nosound false" in lines
    assert "ramsize 268435456" in lines
    assert "screen win/1024/768" in lines
    assert not any(ln.startswith("skip") for ln in lines)  # None dropped


def test_build_prefs_wires_extfs_and_screen(tmp_path):
    files = tmp_path / "drive" / "work" / "datalink" / "files"
    be = _sheep(tmp_path, extfs_dir=str(files), memory_mb=256, screen="win/1024/768")
    prefs = be.build_prefs()
    assert prefs["extfs"] == str(files)  # host<->guest transfer lane
    assert prefs["screen"] == "win/1024/768"  # windowed (NOT dga)
    assert prefs["ramsize"] == 256 * 1024 * 1024
    assert prefs["nogui"] is True and prefs["ether"] == "slirp"
    assert prefs["rom"] == be.rom_path


def test_write_prefs_creates_instance_dir_and_extfs(tmp_path):
    files = tmp_path / "files"
    be = _sheep(tmp_path, extfs_dir=str(files))
    be.write_prefs()
    assert be.prefs_path.exists()
    assert files.is_dir()  # extfs share created
    assert be.snapshots_dir.is_dir()
    assert be.exists() and be.state() == "shut off"


# --- cold snapshot semantics (research/52 §6) ------------------------------
def test_cold_snapshot_copy_revert_delete(tmp_path):
    disk = tmp_path / "macos9.dsk"
    disk.write_bytes(b"golden-state")
    be = _sheep(tmp_path, disk=str(disk))
    assert be.supports_live_snapshot is False
    be.snapshot_create("ready")
    assert be.snapshot_list() == ["ready"]
    disk.write_bytes(b"dirtied")
    be.snapshot_revert("ready")
    assert disk.read_bytes() == b"golden-state"
    be.snapshot_delete("ready")
    assert be.snapshot_list() == []
    with pytest.raises(BackendError):
        be.snapshot_revert("missing")


class _FakeProc:
    """Minimal Popen stand-in: alive => poll()==None, pid == this process."""

    def __init__(self, alive: bool = True) -> None:
        self._alive = alive

    def poll(self):
        return None if self._alive else 0

    @property
    def pid(self) -> int:
        return os.getpid()


def test_snapshot_create_refuses_while_running(tmp_path):
    disk = tmp_path / "macos9.dsk"
    disk.write_bytes(b"golden-state")
    be = _sheep(tmp_path, disk=str(disk))
    be._procs["emulator"] = _FakeProc(alive=True)  # pretend booted
    with pytest.raises(BackendError):
        be.snapshot_create("torn")
    assert be.snapshot_list() == []  # nothing copied while running


def test_is_running_consults_pidfile_across_restart(tmp_path):
    """A restarted controller (empty _procs) still sees the trio via the pidfile,
    so a retry does not duplicate-launch on the same display/port."""
    be = _sheep(tmp_path)
    be.instance_dir.mkdir(parents=True, exist_ok=True)
    # a live pid (this test process) => running even with no in-memory handles
    be.pidfile_path.write_text(json.dumps({"emulator": os.getpid()}))
    assert be._procs == {} and be.is_running() is True
    # a reaped pid => not running
    dead = subprocess.Popen(["/bin/true"])
    dead.wait()
    be.pidfile_path.write_text(json.dumps({"emulator": dead.pid}))
    assert be.is_running() is False


def test_stop_clears_pidfile(tmp_path):
    be = _sheep(tmp_path)
    be.instance_dir.mkdir(parents=True, exist_ok=True)
    dead = subprocess.Popen(["/bin/true"])
    dead.wait()
    be.pidfile_path.write_text(json.dumps({"emulator": dead.pid}))
    be.stop()  # idempotent; already-dead pid, nothing to signal
    assert not be.pidfile_path.exists()


# --- no in-guest agent (host-only MacOS9Module tier) -----------------------
def test_no_guest_agent(tmp_path):
    be = _sheep(tmp_path)
    assert be.guest_ping() is False
    assert be.tap_interface() is None
    assert be.net_info() == {"subnet": None, "interfaces": []}
    for call in (
        lambda: be.guest_exec("/bin/x"),
        lambda: be.guest_write_file("p", b""),
        lambda: be.guest_read_file("p"),
    ):
        with pytest.raises(BackendError):
            call()


# --- host prereqs fail clearly (research/52: "fail clearly if absent") ------
def test_preflight_fails_without_binaries(tmp_path):
    be = _sheep(tmp_path)  # ROM path points at a non-existent file, bins not installed
    with pytest.raises(BackendError):
        be.preflight()


def test_start_fails_clearly_without_rom(tmp_path):
    be = SheepShaverBackend(
        "i",
        settings=MacEmuSettings(newworld_rom="", state_dir=tmp_path),
        disk=str(tmp_path / "d.dsk"),
    )
    with pytest.raises(BackendError):
        be.start()
