"""q800 process backend (research/70c): command construction, QMP-driven lifecycle and
snapshots against a FAKE QMP monitor, the agent's VA1 TCP/serial lanes, and catalog
selection. No QEMU and no ROM needed; the live proof is the golden boot loop."""

import contextlib
import json
import os
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from vmctl_core.agentwire import Reply
from vmctl_core.agentwire.fakeagent import FakeAgent
from vmctl_core.backends import (
    BackendError,
    MacEmuSettings,
    Q800Backend,
    VMBackend,
    backend_for,
    clone_q800,
    is_process_backend,
    q800_spec,
    resolve_backend_kind,
)
from vmctl_core.backends.qemu_q800 import DECLROM_IN_IMAGE, qcode, qcow2_backing_chain
from vmctl_core.catalog import BaseImage, Hardware
from vmctl_core.guestos.registry import default_registry

ROM_HEAD = bytes.fromhex("F1ACAD13")


def _base(**hw):
    hw.setdefault("arch", "m68k")
    hw.setdefault("machine", "q800")
    hw.setdefault("backend", "q800")
    hw.setdefault("memory_mb", 128)
    hw.setdefault("nvram", "q800-753-pram.qcow2")
    hw.setdefault("usb_tablet", False)
    return BaseImage(id="q800-system753", path="q800-753.qcow2", os="system-7.5.3", agent=True,
                     hw=Hardware(**hw))  # fmt: skip


def _settings(tmp_path, **kw):
    rom = tmp_path / "q800.rom"
    rom.write_bytes(ROM_HEAD + b"\0" * 60)
    exe = tmp_path / "qemu-system-m68k"
    exe.write_text("#!/bin/sh\nexit 0\n")
    exe.chmod(exe.stat().st_mode | stat.S_IEXEC)
    kw.setdefault("qemu_m68k_bin", str(exe))
    return MacEmuSettings(rom_68k=str(rom), state_dir=tmp_path / "state", **kw)


def _defined(tmp_path, **spec_kw):
    """A defined (not running) backend with real disk/pram placeholder files."""
    d = tmp_path / "inst"
    d.mkdir()
    disk, pram = tmp_path / "disk.qcow2", d / "pram.qcow2"
    disk.write_bytes(b"x")
    pram.write_bytes(b"x")
    spec = q800_spec(_base(), disk=disk, pram=pram, **spec_kw)
    sp = tmp_path / "def.json"
    sp.write_text(json.dumps(spec))
    be = Q800Backend("rvmc-p-abc123", instance_dir=d, settings=_settings(tmp_path))
    be.define(str(sp))
    return be


# --- fake QMP monitor ---------------------------------------------------------
class FakeQMP:
    def __init__(self, path: Path, snapshots=None):
        self.path, self.cmds = path, []
        self.snaps = dict(snapshots or {})  # tag -> vm size bytes
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(str(path))
        self.sock.listen(8)
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn, conn.makefile("rwb") as f:
                f.write(b'{"QMP": {"version": {}, "capabilities": []}}\n')
                f.flush()
                for line in f:
                    msg = json.loads(line)
                    self.cmds.append(msg)
                    f.write(json.dumps({"return": self._answer(msg)}).encode() + b"\n")
                    f.flush()

    def _answer(self, msg):
        cmd, args = msg["execute"], msg.get("arguments", {})
        if cmd == "query-status":
            return {"status": "running", "running": True}
        if cmd == "add-fd":
            return {"fdset-id": 7, "fd": 42}
        if cmd == "screendump":
            Path(args["filename"]).write_bytes(b"\x89PNG fake")
            return {}
        if cmd == "human-monitor-command":
            words = args["command-line"].split()
            if words[:2] == ["info", "snapshots"]:
                rows = [
                    f"{i + 1}  {t}  {s // (1 << 20)} MiB 2026-10-05 12:00:00 00:00:10.000  0"
                    for i, (t, s) in enumerate(self.snaps.items())
                ]
                return (
                    "List of snapshots present on all disks:\nID  TAG  VM SIZE  DATE  VM CLOCK  ICOUNT\n"
                    + "\n".join(rows)
                )
            if words[0] == "savevm":
                self.snaps[words[1]] = 130 << 20
            if words[0] == "delvm":
                self.snaps.pop(words[1], None)
            return ""
        return {}

    def executed(self, name):
        return [c for c in self.cmds if c["execute"] == name]

    def hmp_lines(self):
        return [c["arguments"]["command-line"] for c in self.executed("human-monitor-command")]

    def close(self):
        self.sock.close()


@pytest.fixture
def running(tmp_path):
    """A backend that looks RUNNING: runtime.json points at a live process whose argv
    carries the QMP socket path (the pid-reuse guard), and a fake QMP answers."""
    be = _defined(tmp_path)
    qmp = FakeQMP(be.qmp_path, snapshots={"ready": 130 << 20})
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(60)", str(be.qmp_path)],
        start_new_session=True,  # like start(): stop() signals the process group
    )
    be.runtime_path.write_text(json.dumps({"pid": proc.pid}))
    yield be, qmp
    proc.kill()
    proc.wait()
    qmp.close()


# --- protocol + selection -------------------------------------------------------
def test_satisfies_vmbackend_protocol(tmp_path):
    assert isinstance(
        Q800Backend("x", instance_dir=tmp_path, settings=_settings(tmp_path)), VMBackend
    )


def test_catalog_selects_q800(tmp_path):
    assert resolve_backend_kind(_base()) == "q800"
    assert resolve_backend_kind(_base(backend="")) == "q800"  # m68k + machine q800 inferred
    assert resolve_backend_kind(_base(backend="", machine="")) == "basilisk2"
    assert is_process_backend(_base())
    be = backend_for(_base(), "d", instance_dir=str(tmp_path), mac_settings=_settings(tmp_path))
    assert isinstance(be, Q800Backend)
    with pytest.raises(ValueError):
        backend_for(_base(), "d")  # no instance_dir


def test_system7_resolves_to_its_own_module():
    mod = default_registry.for_os("system-7.5.3")
    assert mod.display_name.startswith("System 7")
    assert default_registry.for_os("mac-os-9.2.2").display_name.startswith("Mac OS 9")


# --- command construction ---------------------------------------------------------
def test_argv_shape(tmp_path):
    be = _defined(tmp_path, cdrom="/media/doors-apm.iso")
    spec = be.spec()
    argv = be.build_argv(spec)
    s = " ".join(argv)
    assert argv[0].endswith("qemu-system-m68k")
    assert "-M q800,audiodev=snd0" in s and "-m 128" in s and "-g 640x480x8" in s
    assert f"-bios {be.settings.rom_68k}" in s
    assert f"file={spec['pram']},format=qcow2,if=mtd" in argv  # qcow2 PRAM => savevm works
    assert f"file={spec['disk']},format=qcow2,if=none,id=hd0" in argv
    assert "scsi-hd,scsi-id=0,drive=hd0" in argv
    assert "file=/media/doors-apm.iso,format=raw,media=cdrom,if=none,id=cd0,read-only=on" in argv
    assert "scsi-cd,scsi-id=3,drive=cd0,id=cd" in argv
    # agent hostfwd on the instance's unix socket; restrict=on = no route to host/network
    assert f"user,model=dp83932,hostfwd=unix:{be.agent_sock_path}-:9009,restrict=on" in argv
    serials = [argv[i + 1] for i, a in enumerate(argv) if a == "-serial"]
    assert serials == [  # ESCC order: A (modem) then B (printer)
        f"unix:{be.serial_path('a')},server=on,wait=off",
        f"unix:{be.serial_path('b')},server=on,wait=off",
    ]
    assert f"vnc=unix:{be.vnc_path}" in argv  # no TCP listener at all
    assert "virtio-tablet-device" not in argv  # tablet off in this base
    assert f"unix:{be.qmp_path},server=on,wait=off" in argv
    assert "-loadvm" not in argv
    with_loadvm = be.build_argv(spec, loadvm="ready")
    assert with_loadvm[-2:] == ["-loadvm", "ready"]


def test_argv_empty_cd_tap_and_launch_prefix(tmp_path):
    be = _defined(tmp_path, net={"mode": "tap", "ifname": "vnet9", "mac": "52:54:00:aa:bb:cc",
                                 "ip": "192.168.122.50"})  # fmt: skip
    be.settings.q800_launch_prefix = "systemd-run --user --scope --quiet --"
    argv = be.build_argv(be.spec())
    assert be._launch_argv(be.spec(), argv)[:5] == [
        "systemd-run", "--user", "--scope", "--quiet", "--",
    ]  # fmt: skip
    assert "media=cdrom,if=none,id=cd0,read-only=on" in argv  # empty, no format, hot-changeable
    assert "tap,ifname=vnet9,script=no,downscript=no,model=dp83932,mac=52:54:00:aa:bb:cc" in argv
    assert be.tap_interface() == "vnet9" and be.guest_ip() == "192.168.122.50"


def test_qcodes():
    assert [qcode(k) for k in ("KEY_LEFTMETA", "KEY_Q", "KEY_ENTER", "KEY_POWER", "KEY_F1")] == [
        "meta_l", "q", "ret", "power", "f1",
    ]  # fmt: skip


# --- preflight -----------------------------------------------------------------
def test_preflight_rom_pins(tmp_path):
    be = _defined(tmp_path)
    spec = be.spec()
    be.preflight({**spec, "rom_checksum": "F1ACAD13"})
    with pytest.raises(BackendError, match="checksum"):
        be.preflight({**spec, "rom_checksum": "420DBFF3"})
    with pytest.raises(BackendError, match="sha256"):
        be.preflight({**spec, "rom_sha256": "00" * 32})
    be.settings.rom_68k = ""
    with pytest.raises(BackendError, match="VMCTL_ROM_68K"):
        be.preflight(spec)


def test_preflight_missing_binary(tmp_path):
    be = _defined(tmp_path)
    be.settings.qemu_m68k_bin = "/nonexistent/qemu-system-m68k"
    with pytest.raises(BackendError, match="VMCTL_QEMU_M68K_BIN"):
        be.preflight()


def test_start_surfaces_qemu_failure(tmp_path):
    be = _defined(tmp_path)
    exe = tmp_path / "failing-qemu"
    exe.write_text("#!/bin/sh\necho 'qemu: could not load ROM' >&2\nexit 1\n")
    exe.chmod(0o755)
    be.settings.qemu_m68k_bin = str(exe)
    with pytest.raises(BackendError, match="could not load ROM"):
        be.start()
    assert not be.runtime_path.exists() and be.state() == "shut off"


# --- state + QMP-driven operations ---------------------------------------------------
def test_state_and_vnc(tmp_path, running):
    be, _ = running
    assert be.is_running() and be.state() == "running"
    assert be.vnc_endpoint() == ("unix_socket", str(be.vnc_path))
    sub = tmp_path / "other"
    sub.mkdir()
    stopped = _defined(sub)
    assert stopped.state() == "shut off" and stopped.vnc_endpoint() is None
    assert (
        Q800Backend("u", instance_dir=tmp_path / "nope", settings=be.settings).state()
        == "undefined"
    )


def test_live_snapshots_via_hmp(running):
    be, qmp = running
    assert be.snapshot_list() == ["ready"]
    be.snapshot_create("probe")
    be.snapshot_create("ready")  # overwrite = delvm + savevm
    be.snapshot_revert("ready")
    be.snapshot_delete("probe")
    assert qmp.hmp_lines() == [
        "info snapshots",  # snapshot_list
        "info snapshots", "savevm probe",
        "info snapshots", "delvm ready", "savevm ready",
        "info snapshots", "loadvm ready",
        "info snapshots", "delvm probe",
    ]  # fmt: skip
    with pytest.raises(BackendError, match="not found"):
        be.snapshot_revert("nope")
    with pytest.raises(BackendError, match="invalid snapshot name"):
        be.snapshot_create("a b;quit")


def test_screendump_keys_cd_reset(running, tmp_path):
    be, qmp = running
    assert be.screenshot() == b"\x89PNG fake"
    assert qmp.executed("screendump")[0]["arguments"]["format"] == "png"
    assert not list(be.instance_dir.glob("shot-*.png"))  # temp file removed
    be.send_key(["KEY_LEFTMETA", "KEY_Q"])
    assert qmp.executed("send-key")[0]["arguments"]["keys"] == [
        {"type": "qcode", "data": "meta_l"}, {"type": "qcode", "data": "q"},
    ]  # fmt: skip
    be.insert_cd("/x/doors-apm.iso")
    ch = qmp.executed("blockdev-change-medium")[0]["arguments"]
    assert ch["id"] == "cd" and ch["filename"] == "/x/doors-apm.iso"
    assert be.spec()["cdrom"] == "/x/doors-apm.iso"  # persisted for the next boot
    be.eject_cd()
    assert qmp.executed("eject") and be.spec()["cdrom"] is None
    assert not qmp.executed("system_reset")  # white-screens a q800; reset = stop + start


def test_shutdown_asks_the_agent_first(running):
    be, qmp = running

    class ShutdownAgent(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            reply = super()._tool(ident, tool, args, kind, payload)
            if tool == "shutdown":
                os.kill(be._pid(), 9)
            return reply

    with ShutdownAgent().listen(str(be.agent_sock_path)):
        assert be.shutdown_clean(step_timeout=5) == "agent"
    assert not qmp.executed("send-key")  # the power key was never needed
    assert not be.is_running() and not be.runtime_path.exists()


def test_shutdown_falls_back_to_power_key_then_hard_stop(running, monkeypatch):
    be, qmp = running  # no agent socket: every agent step fails at connect
    monkeypatch.setattr("vmctl_core.backends.qemu_q800.time.sleep", lambda s: None)
    waits = iter([False, False, True])  # agent, cmd-q, power-key
    monkeypatch.setattr(be, "_wait_exit", lambda t: next(waits, True))
    monkeypatch.setattr(be, "_stop", lambda: None)
    assert be.shutdown_clean(step_timeout=1) == "power-key"
    keys = [[k["data"] for k in c["arguments"]["keys"]] for c in qmp.executed("send-key")]
    assert keys == [["meta_l", "q"], ["power"], ["ret"]]  # QMP Cmd-Q (no agent), then the power key


def test_shutdown_ladder_cmd_q_then_power_key(running, monkeypatch):
    """A projector in front ignores the Finder; Cmd-Q goes to each front app until the Finder is
    in front; if that does not end it, use the QMP power key."""
    be, _ = running
    monkeypatch.setattr("vmctl_core.backends.qemu_q800.time.sleep", lambda s: None)
    fronts = iter(["Example App", "SimpleText", "Finder"])
    calls = []

    def agent_call(tool, arguments=None, **kw):
        calls.append((tool, arguments))
        if tool == "list_processes":
            return Reply({}, "rows", [{"name": next(fronts), "front": "1"}])
        return Reply({}, "-", None)

    monkeypatch.setattr(be, "agent_call", agent_call)
    monkeypatch.setattr(be, "_power_key", lambda: calls.append(("power-key", None)))
    waits = iter([False, False, True])  # agent, cmd-q, power-key
    monkeypatch.setattr(be, "_wait_exit", lambda t: next(waits, True))
    monkeypatch.setattr(be, "_stop", lambda: None)
    assert be.shutdown_clean(step_timeout=1) == "power-key"
    sent = [(t, a) for t, a in calls if t != "list_processes"]
    assert sent == [
        ("shutdown", None), ("send_keys", {"keys": "{cmd}q"}), ("send_keys", {"keys": "{cmd}q"}),
        ("shutdown", None), ("power-key", None),
    ]  # fmt: skip
    assert be.log_path.read_text().strip().endswith(": power-key")


def test_shutdown_hard_stops_after_the_deadline(running, monkeypatch):
    be, _ = running
    monkeypatch.setattr("vmctl_core.backends.qemu_q800.time.sleep", lambda s: None)
    stopped = []
    monkeypatch.setattr(be, "_wait_exit", lambda t: False)
    monkeypatch.setattr(be, "_stop", lambda: stopped.append(1))
    assert be.shutdown_clean(step_timeout=1) == "hard-stop" and stopped == [1]


def test_stop_sends_quit_and_clears_runtime(running):
    be, qmp = running
    pid = be._pid()
    # the fake QMP does not exit on quit -> SIGTERM of the process group follows
    be.stop()
    assert qmp.executed("quit")
    assert not be.runtime_path.exists() and not be.is_running()
    with pytest.raises(ProcessLookupError):
        import os

        os.kill(pid, 0)


# --- stopped snapshots via qemu-img ---------------------------------------------------
def test_offline_snapshots_use_qemu_img_on_disk_and_pram(tmp_path):
    be = _defined(tmp_path)
    log = tmp_path / "qemu-img.log"
    fake = tmp_path / "qemu-img"
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {log}\n'
        'if [ "$2" = "-l" ]; then printf "Snapshot list:\\nID  TAG  VM_SIZE  DATE  VM_CLOCK  ICOUNT\\n'
        '1  ready  0 B 2026-10-05 12:00:00  0000:00:00.000  0\\n"; fi\n'
    )
    fake.chmod(0o755)
    be.settings.qemu_img_bin = str(fake)
    assert be.snapshot_list() == ["ready"]
    be.snapshot_revert("ready")  # disk-only snapshot: applied with -a, stays off
    be.snapshot_create("new")
    calls = log.read_text().splitlines()
    spec = be.spec()
    assert f"snapshot -a ready {spec['disk']}" in calls
    assert f"snapshot -a ready {spec['pram']}" in calls
    assert f"snapshot -c new {spec['disk']}" in calls and f"snapshot -c new {spec['pram']}" in calls
    assert be.state() == "shut off"


# --- agent: HTTP, then serial ---------------------------------------------------------


# --- clone --------------------------------------------------------------------------
def test_clone_q800_overlays_disk_and_pram(tmp_path):
    cat = tmp_path / "bases"
    cat.mkdir()
    (cat / "q800-753.qcow2").write_bytes(b"g")
    (cat / "q800-753-pram.qcow2").write_bytes(b"p")
    log = tmp_path / "qi.log"
    fake = tmp_path / "qemu-img"
    fake.write_text(f'#!/bin/sh\necho "$@" >> {log}\nfor a; do last=$a; done\n: > "$last"\n')
    fake.chmod(0o755)
    inst = tmp_path / "q800" / "rvmc-p-abc123"
    overlay, spec_path = clone_q800(
        _base(rom_checksum="F1ACAD13"), catalog_dir=cat, domain_name="rvmc-p-abc123",
        overlays_dir=tmp_path / "ov", spec_dir=tmp_path / "xml", instance_dir=inst,
        qemu_img=str(fake),
    )  # fmt: skip
    calls = log.read_text().splitlines()
    assert calls[0].endswith(f"-b {cat / 'q800-753.qcow2'} {overlay}")
    assert calls[1].endswith(f"-b {cat / 'q800-753-pram.qcow2'} {inst / 'pram.qcow2'}")
    spec = json.loads(spec_path.read_text())
    assert spec["kind"] == "q800" and spec["disk"] == str(overlay)
    assert spec["pram"] == str(inst / "pram.qcow2") and spec["rom_checksum"] == "F1ACAD13"
    with pytest.raises(BackendError, match=r"hw\.nvram"):
        clone_q800(_base(nvram=""), catalog_dir=cat, domain_name="d", overlays_dir=tmp_path,
                   spec_dir=tmp_path, instance_dir=tmp_path / "i")  # fmt: skip


def test_undefine_removes_instance_dir(tmp_path):
    be = _defined(tmp_path)
    assert be.exists()
    be.undefine()
    assert not be.instance_dir.exists() and be.state() == "undefined"


def test_system7_module_reads_agent_log():
    class Ctx:
        def guest_read_file(self, path):
            assert path.endswith("Preferences:rvmc-agent68k.log")
            return b"start\rip=a000\r\r"

    recs = default_registry.for_os("system-7.5.3").read_logs(Ctx())
    assert [r.message for r in recs] == ["start", "ip=a000"]


def _fake_qemu_img(tmp_path, pram_vm_size: str):
    """qemu-img stand-in: 'ready' lists with RAM state on the PRAM only (QEMU puts the
    vm state on the first writable qcow2 = the PRAM)."""
    log = tmp_path / "qi.log"
    fake = tmp_path / "qemu-img-pram"
    fake.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> {log}\n'
        'if [ "$2" = "-l" ]; then size="0 B"; case "$3" in *pram*) size="'
        + pram_vm_size
        + '";; esac\n'
        '  printf "Snapshot list:\\nID TAG VM_SIZE DATE VM_CLOCK ICOUNT\\n'
        '1 ready $size 2026-10-05 12:00:00 0000:00:10.000 0\\n"; fi\n'
    )
    fake.chmod(0o755)
    return fake, log


def test_offline_revert_detects_ram_state_on_pram(tmp_path, monkeypatch):
    be = _defined(tmp_path)
    be.settings.qemu_img_bin, _ = map(str, _fake_qemu_img(tmp_path, "130 MiB"))
    started = []
    monkeypatch.setattr(be, "start", lambda **kw: started.append(kw))
    be.snapshot_revert("ready")
    assert started == [{"loadvm": "ready"}]  # boots into the RAM state, not a disk-only apply


def test_running_revert_of_disk_only_snapshot_power_cycles(running, tmp_path, monkeypatch):
    be, qmp = running
    qmp.snaps = {"cold": 0}
    calls = []
    monkeypatch.setattr(be, "stop", lambda: calls.append("stop"))
    monkeypatch.setattr(be, "start", lambda **kw: calls.append("start"))
    monkeypatch.setattr(be, "_qemu_img", lambda *a: calls.append(" ".join(a[:3])) or "")
    be.snapshot_revert("cold")
    assert calls == ["stop", "snapshot -a cold", "snapshot -a cold", "start"]
    assert "loadvm cold" not in qmp.hmp_lines()


def test_clone_rejects_traversal(tmp_path):
    with pytest.raises(ValueError):
        clone_q800(_base(), catalog_dir=tmp_path, domain_name="../victim", overlays_dir=tmp_path,
                   spec_dir=tmp_path, instance_dir=tmp_path / "i")  # fmt: skip


def test_memory_is_validated_before_it_is_persisted(tmp_path):
    be = _defined(tmp_path)
    with pytest.raises(ValueError):
        be.set_settings(memory_mb=-1)
    assert be.get_settings()["memory_mb"] == 128
    be.set_settings(memory_mb=256)
    assert be.spec()["memory_mb"] == 256


def test_unexpected_qemu_exit_is_reported_with_the_log(tmp_path):
    be = _defined(tmp_path)
    be.runtime_path.write_text(json.dumps({"pid": 999999999}))
    be.log_path.write_text("qemu: fatal: DOUBLE MMU FAULT\n")
    with pytest.raises(BackendError, match="DOUBLE MMU FAULT"):
        be.agent_call("ping", lanes=("http",))


def test_savevm_waits_for_the_agent_to_settle(running, monkeypatch):
    from vmctl_core.backends import qemu_q800

    be, qmp = running
    slept = []
    monkeypatch.setattr(qemu_q800.time, "sleep", lambda s: slept.append(s))
    qemu_q800._LAST_AGENT_CALL[str(be.instance_dir)] = qemu_q800.time.monotonic()
    be.snapshot_create("probe")
    assert slept and 1.5 < slept[0] <= qemu_q800.SNAPSHOT_QUIESCE_S
    assert "savevm probe" in qmp.hmp_lines()


def test_live_disk_only_snapshot_is_refused(running):
    be, _ = running
    with pytest.raises(BackendError, match="always includes RAM"):
        be.snapshot_create("x", memory=False)


def test_concurrent_starts_launch_one_qemu(tmp_path, monkeypatch):
    be = _defined(tmp_path)
    launched = []

    def fake_start(self, *, loadvm=""):
        if launched:  # second caller sees the first one's process
            return
        time.sleep(0.2)
        launched.append(1)

    monkeypatch.setattr(Q800Backend, "_start", fake_start)
    ths = [threading.Thread(target=be.start) for _ in range(3)]
    [t.start() for t in ths]
    [t.join() for t in ths]
    assert launched == [1]


# --- emulator image (container) mode ---------------------------------------------------
IMAGE_ID = "sha256:" + "ab" * 32

FAKE_QMP_PROC = r"""
import json, os, socket, sys
path = sys.argv[1]
srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
srv.bind(path)
srv.listen(4)
while True:
    conn, _ = srv.accept()
    with conn, conn.makefile("rwb") as f:
        f.write(b'{"QMP": {}}\n'); f.flush()
        for line in f:
            cmd = json.loads(line)["execute"]
            ret = {"status": "running"} if cmd == "query-status" else {}
            f.write(json.dumps({"return": ret}).encode() + b"\n"); f.flush()
            if cmd == "quit":
                os._exit(0)
"""

FAKE_DOCKER = r"""
import json, os, signal, subprocess, sys
from pathlib import Path
a = sys.argv[1:]
state = Path(os.environ["FAKE_DOCKER_STATE"])
with open(state / "calls.jsonl", "a") as f:
    f.write(json.dumps(a) + "\n")
if a[:2] == ["image", "inspect"]:
    if a[-1] in os.environ.get("FAKE_DOCKER_IMAGES", "").split():
        print(a[-1])
        sys.exit(0)
    sys.exit(1)
if a[0] == "rm":
    pidf = state / (a[-1] + ".pid")
    if pidf.exists():
        try:
            os.kill(int(pidf.read_text()), signal.SIGKILL)
        except ProcessLookupError:
            pass
        pidf.unlink()
    sys.exit(0)
if a[0] == "inspect":
    pidf = state / (a[-1] + ".pid")
    if not pidf.exists():
        sys.exit(1)
    print(pidf.read_text())
    sys.exit(0)
if a[0] == "run":
    i = next(n for n, x in enumerate(a) if x.startswith("sha256:"))
    cmd = a[i + 1:]
    if "-d" in a[:i]:
        qmp = cmd[cmd.index("-qmp") + 1].split(":", 1)[1].split(",")[0]
        p = subprocess.Popen([sys.executable, os.environ["FAKE_QMP_PROC"], qmp],
                             start_new_session=True, stdout=subprocess.DEVNULL,
                             stderr=subprocess.DEVNULL)
        (state / (a[a.index("--name") + 1] + ".pid")).write_text(str(p.pid))
        print("c0ffee")
        sys.exit(0)
    os.execv(os.environ["FAKE_QEMU_IMG"], [os.environ["FAKE_QEMU_IMG"], *cmd[1:]])
"""


def _qcow2(path: Path, backing: str = "") -> None:
    """A minimal qcow2 header (magic, version, backing file offset/size + name)."""
    name = backing.encode()
    hdr = b"QFI\xfb" + (3).to_bytes(4, "big") + (72 if name else 0).to_bytes(8, "big")
    hdr += len(name).to_bytes(4, "big")
    path.write_bytes(hdr.ljust(72, b"\0") + name)


@pytest.fixture
def docker_env(tmp_path, monkeypatch):
    state = tmp_path / "docker-state"
    state.mkdir()
    fake = tmp_path / "docker"
    fake.write_text(f"#!{sys.executable}\n{FAKE_DOCKER}")
    fake.chmod(0o755)
    qmp_proc = tmp_path / "fake_qmp_proc.py"
    qmp_proc.write_text(FAKE_QMP_PROC)
    qimg = tmp_path / "fake-qemu-img"
    qimg.write_text(
        f'#!/bin/sh\necho "$@" >> {state}/qemu-img.log\nfor a; do last=$a; done\n: > "$last"\n'
    )
    qimg.chmod(0o755)
    monkeypatch.setenv("FAKE_DOCKER_STATE", str(state))
    monkeypatch.setenv("FAKE_DOCKER_IMAGES", IMAGE_ID)
    monkeypatch.setenv("FAKE_QMP_PROC", str(qmp_proc))
    monkeypatch.setenv("FAKE_QEMU_IMG", str(qimg))

    def calls():
        return [json.loads(x) for x in (state / "calls.jsonl").read_text().splitlines()]

    yield str(fake), calls
    for pidf in state.glob("*.pid"):
        with contextlib.suppress(ProcessLookupError):
            os.kill(int(pidf.read_text()), 9)


def _image_backend(tmp_path, docker, **hw):
    cat = tmp_path / "bases"
    cat.mkdir()
    _qcow2(cat / "golden.qcow2")
    d = tmp_path / "q800" / "rvmc-p-img001"
    d.mkdir(parents=True)
    disk, pram = tmp_path / "ov.qcow2", d / "pram.qcow2"
    _qcow2(disk, str(cat / "golden.qcow2"))
    _qcow2(pram, "../../bases/golden.qcow2")  # relative: resolved against pram's dir
    base = _base(emulator_image="reg/vmctl-emu/qemu-m68k:11.1.1-zkm1", emulator_image_id=IMAGE_ID,
                 **hw)  # fmt: skip
    spec = q800_spec(base, disk=disk, pram=pram, cdrom=str(tmp_path / "doors.iso"))
    sp = tmp_path / "def.json"
    sp.write_text(json.dumps(spec))
    be = Q800Backend(
        "rvmc-p-img001", instance_dir=d, settings=_settings(tmp_path, docker_bin=docker)
    )
    be.define(str(sp))
    return be, cat


def test_backing_chain_resolves_like_qemu(tmp_path):
    (tmp_path / "a").mkdir()
    _qcow2(tmp_path / "base.qcow2")
    _qcow2(tmp_path / "a" / "mid.qcow2", "../base.qcow2")
    _qcow2(tmp_path / "top.qcow2", str(tmp_path / "a" / "mid.qcow2"))
    assert qcow2_backing_chain(tmp_path / "top.qcow2") == [
        tmp_path / "a" / "mid.qcow2", tmp_path / "a" / "../base.qcow2",
    ]  # fmt: skip
    (tmp_path / "raw.img").write_bytes(b"\0" * 100)
    assert qcow2_backing_chain(tmp_path / "raw.img") == []


def test_container_start_stop(tmp_path, docker_env):
    docker, calls = docker_env
    be, cat = _image_backend(tmp_path, docker)
    be.start()
    assert be.is_running() and be.state() == "running"
    run = next(c for c in calls() if c[0] == "run")
    i = run.index(IMAGE_ID)
    opts, inner = run[:i], run[i + 1 :]
    for flag in (["--network", "none"], ["--cap-drop", "ALL"], ["--read-only"], ["-d"], ["--rm"],
                 ["--security-opt", "no-new-privileges"]):  # fmt: skip
        assert " ".join(flag) in " ".join(opts)
    assert opts[opts.index("--user") + 1] == f"{os.getuid()}:{os.getgid()}"
    mounts = [opts[n + 1] for n, x in enumerate(opts) if x == "--mount"]
    spec = be.spec()
    golden = cat / "golden.qcow2"
    assert f"type=bind,source={be.instance_dir},target={be.instance_dir}" in mounts
    assert f"type=bind,source={spec['disk']},target={spec['disk']}" in mounts  # rw overlay
    assert f"type=bind,source={golden},target={golden},readonly" in mounts  # read-only golden
    assert any(m.endswith("q800.rom,readonly") for m in mounts)
    assert any(m.endswith("doors.iso,readonly") for m in mounts)
    labels = [opts[n + 1] for n, x in enumerate(opts) if x == "--label"]
    assert "vmctl.kind=q800" in labels and "vmctl.instance=rvmc-p-img001" in labels
    assert opts[opts.index("--name") + 1] == be.container_name
    assert inner[:2] == ["sh", "-c"] and "socat UNIX-LISTEN" in inner[2]
    assert inner[3:5] == [str(be.log_path), str(be.agent_sock_path)]
    assert inner[5] == "qemu-system-m68k"  # the image's binary, not VMCTL_QEMU_M68K_BIN
    # agent forward on the container's own loopback, bridged to agent.sock by socat
    assert "user,model=dp83932,hostfwd=tcp:127.0.0.1:9009-:9009,restrict=on" in inner
    assert json.loads(be.runtime_path.read_text())["container"] == be.container_name
    be.stop()
    assert not be.is_running() and not be.runtime_path.exists()
    assert ["rm", "-f", be.container_name] in calls()


def test_container_preflight_names_the_missing_image(tmp_path, docker_env, monkeypatch):
    docker, _ = docker_env
    be, _ = _image_backend(tmp_path, docker)
    monkeypatch.setenv("FAKE_DOCKER_IMAGES", "")
    with pytest.raises(BackendError, match=r"docker pull reg/vmctl-emu/qemu-m68k:11\.1\.1-zkm1"):
        be.preflight()
    with pytest.raises(BackendError, match="sha256 image id"):
        be.preflight({**be.spec(), "emulator_image_id": "latest"})
    with pytest.raises(BackendError, match="tap networking"):
        monkeypatch.setenv("FAKE_DOCKER_IMAGES", IMAGE_ID)
        be.preflight({**be.spec(), "net": {"mode": "tap", "ifname": "t0"}})


def test_container_tablet_uses_the_image_declrom(tmp_path, docker_env):
    docker, _ = docker_env
    be, _ = _image_backend(tmp_path, docker, usb_tablet=True)
    argv = be.build_argv(be.spec())
    assert f"nubus-virtio-mmio,romfile={DECLROM_IN_IMAGE}" in argv
    assert "virtio-tablet-device" in argv
    (tmp_path / "d").mkdir()
    direct = _defined(tmp_path / "d")
    with pytest.raises(BackendError, match="VMCTL_Q800_DECLROM"):
        direct.preflight({**direct.spec(), "tablet": True})


def test_container_hot_cd_passes_an_fd(running, tmp_path):
    be, qmp = running
    spec = be.spec()
    be._write_spec({**spec, "emulator_image_id": IMAGE_ID})
    iso = tmp_path / "late.iso"
    iso.write_bytes(b"iso")
    be.insert_cd(str(iso))
    # one monitor connection for all three (an fd set dies with the connection that added it)
    assert [c["execute"] for c in qmp.cmds] == [
        "qmp_capabilities", "add-fd", "blockdev-change-medium", "remove-fd",
    ]  # fmt: skip
    fdset = qmp.executed("add-fd")[0]["arguments"]["fdset-id"]
    ch = qmp.executed("blockdev-change-medium")[0]["arguments"]
    assert ch["filename"] == f"/dev/fdset/{fdset}" and ch["read-only-mode"] == "read-only"
    assert qmp.executed("remove-fd")[0]["arguments"] == {"fdset-id": fdset}
    assert be.spec()["cdrom"] == str(iso)


def test_clone_with_image_runs_qemu_img_in_the_image(tmp_path, docker_env):
    docker, calls = docker_env
    cat = tmp_path / "bases"
    cat.mkdir()
    _qcow2(cat / "q800-753.qcow2")
    _qcow2(cat / "q800-753-pram.qcow2")
    base = _base(emulator_image_id=IMAGE_ID)
    inst = tmp_path / "q800" / "rvmc-p-c1"
    overlay, _ = clone_q800(
        base, catalog_dir=cat, domain_name="rvmc-p-c1", overlays_dir=tmp_path / "ov",
        spec_dir=tmp_path / "xml", instance_dir=inst,
        settings=_settings(tmp_path, docker_bin=docker),
    )  # fmt: skip
    runs = [c for c in calls() if c[0] == "run"]
    assert len(runs) == 2 and all("--network" in r and IMAGE_ID in r for r in runs)
    inner = runs[0][runs[0].index(IMAGE_ID) + 1 :]
    assert inner == ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b",
                     str(cat / "q800-753.qcow2"), str(overlay)]  # fmt: skip
    assert (
        f"type=bind,source={cat / 'q800-753.qcow2'},target={cat / 'q800-753.qcow2'},readonly"
        in runs[0]
    )


def test_clone_with_relative_dirs_writes_absolute_paths(tmp_path, monkeypatch, docker_env):
    """rvmc's default state dir is relative (.rvmc): every path that reaches the container
    (qemu-img argv, spec, backend argv) must be absolute."""
    docker, calls = docker_env
    monkeypatch.chdir(tmp_path)
    (tmp_path / "bases").mkdir()
    _qcow2(tmp_path / "bases" / "q800-753.qcow2")
    _qcow2(tmp_path / "bases" / "q800-753-pram.qcow2")
    overlay, spec_path = clone_q800(
        _base(emulator_image_id=IMAGE_ID), catalog_dir=Path("bases"), domain_name="r1",
        overlays_dir=Path(".rvmc/overlays"), spec_dir=Path(".rvmc/xml"),
        instance_dir=Path(".rvmc/q800/r1"), settings=_settings(tmp_path, docker_bin=docker),
    )  # fmt: skip
    assert overlay.is_absolute()
    run = next(c for c in calls() if c[0] == "run")
    assert run[-3] == "-b" and all(a.startswith("/") for a in run[-2:])  # -b SRC DST
    spec = json.loads(spec_path.read_text())
    assert Path(spec["disk"]).is_absolute() and Path(spec["pram"]).is_absolute()
    be = Q800Backend("r1", instance_dir=Path(".rvmc/q800/r1"), settings=_settings(tmp_path))
    assert be.qmp_path.is_absolute()


def test_concurrent_definition_updates_keep_both(tmp_path):
    be = _defined(tmp_path)
    ths = [threading.Thread(target=be.insert_cd, args=(f"/x/{i}.iso",)) for i in range(5)]
    ths += [
        threading.Thread(target=be.set_settings, kwargs={"memory_mb": 64 + i}) for i in range(5)
    ]
    [t.start() for t in ths]
    [t.join() for t in ths]
    spec = be.spec()
    assert spec["cdrom"].endswith(".iso") and 64 <= spec["memory_mb"] <= 68
    assert not list(be.instance_dir.glob("*.tmp"))


def test_system7_log_read_takes_tail():
    class Ctx:
        def guest_read_file(self, path):
            return b"old1\rold2\rnew1\rnew2\r"

    recs = default_registry.for_os("system-7.5.3").read_logs(Ctx(), count=2)
    assert [r.message for r in recs] == ["new1", "new2"]


# --- audio (ASC -> host PipeWire null sink) ---------------------------------------
def test_audio_sink_switches_the_audiodev_and_mounts_pipewire(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", "/run/user/4242")
    be, _ = _image_backend(tmp_path, "docker")
    spec = be.spec()
    argv = be.build_argv(spec)
    assert argv[argv.index("-audiodev") + 1] == "none,id=snd0"  # default: silent
    assert "XDG_RUNTIME_DIR=/run/user/4242" not in be._launch_argv(spec, argv)
    spec["audio_sink"] = "rvmc-abc123"
    argv = be.build_argv(spec)
    assert argv[argv.index("-audiodev") + 1] == "pipewire,id=snd0,out.name=rvmc-abc123"
    assert "q800,audiodev=snd0" in argv  # the ASC stays bound to snd0
    launch = be._launch_argv(spec, argv)
    assert launch[launch.index("-e") + 1] == "XDG_RUNTIME_DIR=/run/user/4242"
    sock = "/run/user/4242/pipewire-0"
    assert f"type=bind,source={sock},target={sock}" in launch  # rw: clients write to it


def test_audio_sink_needs_a_pipewire_build(tmp_path, monkeypatch):
    be = _defined(tmp_path)
    monkeypatch.setattr(Q800Backend, "audio_drivers", lambda self: ["none", "oss", "wav"])
    with pytest.raises(BackendError, match="no pipewire audiodev"):
        be.set_settings(audio_sink="rvmc-abc123")
    assert "audio_sink" not in be.spec()
    with pytest.raises(ValueError, match="must not contain"):
        be.set_settings(audio_sink="x,server=evil")
    monkeypatch.setattr(Q800Backend, "audio_drivers", lambda self: ["none", "pipewire"])
    be.set_settings(audio_sink="rvmc-abc123")
    assert be.spec()["audio_sink"] == "rvmc-abc123"
    be.set_settings(audio_sink="")  # off needs no probe
    assert be.spec()["audio_sink"] == ""


def test_audio_drivers_parses_qemu_help(tmp_path):
    be = _defined(tmp_path)
    exe = Path(be.settings.qemu_m68k_bin)
    exe.write_text("#!/bin/sh\nprintf 'Available audio drivers:\\nnone\\npipewire\\nwav\\n'\n")
    assert be.audio_drivers() == ["none", "pipewire", "wav"]
