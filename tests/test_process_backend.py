"""ProcessBackend with `sleep` as the emulator: lifecycle, cold snapshots, liveness, contract."""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from vmctl_core.backends import BackendError, ProcessBackend, ProcessSpec, VMBackend


def make(tmp_path, **kw):
    (tmp_path / "disk.img").write_bytes(b"golden")
    spec = ProcessSpec(argv=["sleep", "60"], images=["disk.img"], **kw)
    return ProcessBackend("work", instance_dir=tmp_path, spec=spec)


@pytest.fixture
def backend(tmp_path):
    b = make(tmp_path)
    yield b
    b.stop()


def test_satisfies_the_contract(backend):
    assert isinstance(backend, VMBackend)


def test_loads_the_spec_from_the_instance(tmp_path):
    (tmp_path / "process.json").write_text('{"argv": ["sleep", "1"]}')
    assert ProcessBackend("w", instance_dir=tmp_path).spec.argv == ["sleep", "1"]


def test_lifecycle_is_idempotent_and_survives_a_new_controller(backend, tmp_path):
    assert backend.state() == "shut off"
    backend.start()
    backend.start()
    assert backend.state() == "running"
    # a restarted controller finds the running emulator through the pid file
    again = ProcessBackend("work", instance_dir=tmp_path, spec=backend.spec)
    assert again.is_running()
    again.stop()
    again.stop()
    assert not backend.is_running()


def _wait_for_child(tmp_path):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        text = (tmp_path / "child").read_text() if (tmp_path / "child").exists() else ""
        if text.strip():
            return int(text)
        time.sleep(0.02)
    pytest.fail("no child started")


def _gone(pid):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            if Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z":
                return True
        except OSError:
            return True
        time.sleep(0.02)
    return False


def test_start_clears_helpers_of_a_crashed_run(tmp_path):
    b = make(tmp_path)
    b.spec.argv = ["sh", "-c", "sleep 60 & echo $! > child; exit 1"]
    b.start()
    child = _wait_for_child(tmp_path)
    deadline = time.monotonic() + 3
    while b.is_running() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not b.is_running()
    assert not _gone_now(child)
    b.spec.argv = ["sleep", "60"]
    b.start()
    assert _gone(child)
    b.stop()


def _gone_now(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0] == "Z"
    except OSError:
        return True


def test_stop_ends_the_whole_group(tmp_path):
    b = make(tmp_path)
    b.spec.argv = ["sh", "-c", "sleep 60 & echo $! > child; wait"]
    b.start()
    deadline = time.monotonic() + 3
    while not (tmp_path / "child").exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    child = int((tmp_path / "child").read_text())
    b.stop()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            return
        if " Z " in Path(f"/proc/{child}/stat").read_text():
            return
        time.sleep(0.02)
    pytest.fail("child of the emulator survived stop()")


def test_stop_ends_a_frozen_child_that_ignores_term(tmp_path):
    b = make(tmp_path)
    b.spec.argv = ["sh", "-c", "sleep 60 & echo $! > child; kill -STOP $!; wait"]
    b.start()
    child = _wait_for_child(tmp_path)
    b.stop()
    assert _gone(child), "frozen child survived stop()"


def test_a_crashed_process_counts_as_stopped(tmp_path):
    b = make(tmp_path)
    b.spec.argv = ["true"]
    b.start()
    deadline = time.monotonic() + 3
    while b.is_running() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert b.state() == "shut off"


def test_snapshot_revert_restores_the_images_and_leaves_it_stopped(backend, tmp_path):
    backend.snapshot_create("ready")
    assert backend.snapshot_list() == ["ready"]
    (tmp_path / "disk.img").write_bytes(b"changed")
    backend.start()
    backend.snapshot_revert("ready")
    assert not backend.is_running()
    assert (tmp_path / "disk.img").read_bytes() == b"golden"


def test_a_damaged_snapshot_fails_closed(backend, tmp_path):
    backend.snapshot_create("ready")
    (tmp_path / "snapshots/ready/disk.img").write_bytes(b"bitrot")
    (tmp_path / "disk.img").write_bytes(b"current")
    with pytest.raises(BackendError, match="damaged"):
        backend.snapshot_revert("ready")
    assert (tmp_path / "disk.img").read_bytes() == b"current"


def test_snapshot_needs_a_stopped_emulator(backend):
    backend.start()
    with pytest.raises(BackendError, match="stop"):
        backend.snapshot_create("ready")


def test_refreshing_a_snapshot_keeps_the_old_one_on_failure(backend, tmp_path, monkeypatch):
    backend.snapshot_create("ready")
    (tmp_path / "disk.img").write_bytes(b"new")
    monkeypatch.setattr(
        "vmctl_core.backends.process.shutil.copy2",
        lambda *a: (_ for _ in ()).throw(OSError("disk full")),
    )
    with pytest.raises(OSError):
        backend.snapshot_create("ready")
    assert (tmp_path / "snapshots/ready/disk.img").read_bytes() == b"golden"


def test_liveness_without_an_alive_file_is_the_process(backend):
    assert not backend.guest_ping()
    backend.start()
    assert backend.guest_ping()


def test_liveness_needs_a_fresh_alive_file(tmp_path):
    b = make(tmp_path, alive_file="alive", alive_max_age_s=5)
    b.start()
    try:
        assert not b.guest_ping()  # started, but the work has not reported yet
        (tmp_path / "alive").touch()
        assert b.guest_ping()
        os.utime(tmp_path / "alive", (time.time() - 60, time.time() - 60))
        assert not b.guest_ping()  # process up, work hung
    finally:
        b.stop()


def test_start_clears_a_stale_alive_file(tmp_path):
    b = make(tmp_path, alive_file="alive")
    (tmp_path / "alive").touch()
    b.start()
    try:
        assert not b.guest_ping()
    finally:
        b.stop()


def test_missing_image_refuses_to_start(tmp_path):
    b = make(tmp_path)
    (tmp_path / "disk.img").unlink()
    assert b.state() == "undefined"
    with pytest.raises(BackendError):
        b.start()


@pytest.fixture
def virtual_backend(tmp_path, monkeypatch):
    import sys

    # A private display number avoids touching the desktop's X socket.
    display_num = int.from_bytes(os.urandom(4), "big")
    socket_path = Path(f"/tmp/.X11-unix/X{display_num}")
    socket_path.parent.mkdir(exist_ok=True)
    binaries = tmp_path / "bin"
    binaries.mkdir()
    xvfb = binaries / "Xvfb"
    xvfb.write_text(
        f"#!{sys.executable}\n"
        "import json, os, socket, sys, time\n"
        "from pathlib import Path\n"
        "Path('xvfb.args').write_text(json.dumps(sys.argv[1:]))\n"
        "Path('xvfb.pid').write_text(str(os.getpid()))\n"
        "mode = os.environ.get('XVFB_MODE', '')\n"
        "if mode == 'exit': sys.exit(1)\n"
        "if mode == 'timeout': time.sleep(60)\n"
        "s = socket.socket(socket.AF_UNIX)\n"
        "s.bind('/tmp/.X11-unix/X' + sys.argv[1][1:])\n"
        "s.listen()\n"
        "while True:\n"
        "    client, _ = s.accept()\n"
        "    client.close()\n"
    )
    xvfb.chmod(0o755)
    vnc = binaries / "x11vnc"
    vnc.write_text(
        f"#!{sys.executable}\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path('vnc.args').write_text(json.dumps(sys.argv[1:]))\n"
        "Path('vnc.pid').write_text(str(os.getpid()))\n"
        "os.execlp('sleep', 'sleep', '60')\n"
    )
    vnc.chmod(0o755)
    monkeypatch.setenv("PATH", f"{binaries}:{os.environ['PATH']}")
    b = make(tmp_path, virtual_display=True, display=f":{display_num}", vnc_port=5999)
    yield b
    b.stop()
    socket_path.unlink(missing_ok=True)


def test_virtual_display_group_and_controller_restart(virtual_backend, tmp_path):
    import json

    b = virtual_backend
    b.start()
    try:
        assert b.is_running()
        assert b.vnc_endpoint() == ("127.0.0.1", 5999)
        deadline = time.monotonic() + 3
        while not (tmp_path / "vnc.pid").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        pids = [
            int((tmp_path / p).read_text()) for p in ("xvfb.pid", "vnc.pid", "process.emulator.pid")
        ]
        assert {os.getpgid(pid) for pid in pids} == {int((tmp_path / "process.pid").read_text())}
        args = json.loads((tmp_path / "xvfb.args").read_text())
        assert args == [b.spec.display, "-screen", "0", "1024x768x24", "-nolisten", "tcp"]
        assert json.loads((tmp_path / "vnc.args").read_text()) == [
            "-display",
            b.spec.display,
            "-localhost",
            "-forever",
            "-shared",
            "-rfbport",
            "5999",
        ]
        again = ProcessBackend("work", instance_dir=tmp_path, spec=b.spec)
        again.start()
        assert again._pid() == pids[-1]
        again.stop()
        assert all(_gone(pid) for pid in pids)
        assert not (tmp_path / "process.pid").exists()
        assert not (tmp_path / "process.emulator.pid").exists()
    finally:
        b.stop()


@pytest.mark.parametrize("mode", ["exit", "timeout"])
def test_virtual_display_failure_cleans_group(virtual_backend, tmp_path, monkeypatch, mode):
    monkeypatch.setenv("XVFB_MODE", mode)
    monkeypatch.setattr("vmctl_core.backends.process.DISPLAY_TIMEOUT_S", 0.3)
    with pytest.raises(BackendError, match=r"Xvfb exited|not ready"):
        virtual_backend.start()
    assert _gone(int((tmp_path / "xvfb.pid").read_text()))
    assert not virtual_backend.is_running()
    assert not (tmp_path / "process.pid").exists()
    assert not (tmp_path / "vnc.pid").exists()


def test_missing_emulator_cleans_virtual_helpers(virtual_backend, tmp_path):
    virtual_backend.spec.argv = ["/no/such/emulator"]
    with pytest.raises(BackendError, match="cannot start"):
        virtual_backend.start()
    assert _gone(int((tmp_path / "xvfb.pid").read_text()))
    if (tmp_path / "vnc.pid").exists():
        assert _gone(int((tmp_path / "vnc.pid").read_text()))
    assert not (tmp_path / "process.pid").exists()


@pytest.mark.parametrize("virtual", [False, True])
def test_screenshot_uses_selected_display(tmp_path, monkeypatch, virtual):
    import subprocess

    b = make(tmp_path, virtual_display=virtual, display=":123")

    def run(argv, **kwargs):
        assert argv[argv.index("-i") + 1] == ":123"
        return subprocess.CompletedProcess(argv, 0, stdout=b"png")

    monkeypatch.setattr("vmctl_core.backends.process.subprocess.run", run)
    assert b.screenshot() == b"png"
    if not virtual:
        assert b.vnc_endpoint() is None


def test_virtual_display_refuses_an_existing_server(virtual_backend, tmp_path):
    import socket

    path = f"/tmp/.X11-unix/X{virtual_backend.spec.display[1:]}"
    with socket.socket(socket.AF_UNIX) as server:
        server.bind(path)
        server.listen()
        with pytest.raises(BackendError, match="already in use"):
            virtual_backend.start()
        assert not (tmp_path / "xvfb.pid").exists()
        assert not (tmp_path / "process.pid").exists()


def test_probe_uses_ram_owner_and_keeps_task_sample(tmp_path, monkeypatch):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, probe=ProbeSpec(kind="mac68k", ram_bytes=65536))
    monkeypatch.setattr(b, "_pid", lambda: 100)
    monkeypatch.setattr(b, "_probe_candidates", lambda _: [100, 200])
    calls = []

    def probe(spec, pid, state):
        calls.append(pid)
        if pid == 100:
            return False, {"status": "unreadable"}
        alive = True if "detail" in state else None
        detail = {"status": "ok", "alive": alive, "cur_app": "Finder", "pid": pid}
        state["detail"] = detail
        return alive, detail

    monkeypatch.setattr("vmctl_core.backends.process.probe", probe)
    assert not b.guest_ping()  # warming up preserves the bool backend contract
    assert b.guest_tasks()["alive"] is None
    assert calls == [100, 200]
    assert b.guest_ping()
    assert calls == [100, 200, 200]  # reuse selected RAM owner before wrapper
    assert b.guest_tasks()["cur_app"] == "Finder"
    monkeypatch.setattr(b, "_pid", lambda: None)
    assert b.guest_tasks() == {"alive": False, "status": "stopped"}
    assert b._probe_state == {}


def test_probe_and_alive_file_are_both_required(tmp_path, monkeypatch):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, alive_file="alive", probe=ProbeSpec(kind="mac68k", ram_bytes=65536))
    monkeypatch.setattr(b, "_pid", lambda: 1)
    result = True
    monkeypatch.setattr(b, "_guest_probe", lambda _: (result, {}))
    assert not b.guest_ping()
    (tmp_path / "alive").touch()
    assert b.guest_ping()
    result = False
    assert not b.guest_ping()
    result = True
    os.utime(tmp_path / "alive", (0, 0))
    assert not b.guest_ping()


def test_probe_permission_error_names_ptrace_policy(tmp_path, monkeypatch):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, probe=ProbeSpec(kind="mac68k", ram_bytes=65536))
    monkeypatch.setattr(b, "_pid", lambda: 1)
    monkeypatch.setattr(b, "_probe_candidates", lambda _: [1])

    def denied(*args):
        raise PermissionError("/proc/1/mem")

    monkeypatch.setattr("vmctl_core.backends.process.probe", denied)
    with pytest.raises(BackendError, match=r"kernel\.yama\.ptrace_scope"):
        b.guest_ping()


def test_probe_resolves_kickstart_against_instance(tmp_path, monkeypatch):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, probe=ProbeSpec(kind="amiga", kickstart="roms/kick.rom"))
    monkeypatch.setattr(b, "_pid", lambda: 1)
    monkeypatch.setattr(b, "_probe_candidates", lambda _: [1])

    def probe(spec, pid, state):
        assert spec.kickstart == str(tmp_path / "roms/kick.rom")
        return True, {"status": "ok"}

    monkeypatch.setattr("vmctl_core.backends.process.probe", probe)
    assert b.guest_ping()
    assert b.spec.probe.kickstart == "roms/kick.rom"


@pytest.mark.parametrize("virtual", [False, True])
def test_probe_candidates_prefer_emulator_comm_in_own_group(tmp_path, monkeypatch, virtual):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, probe=ProbeSpec(kind="amiga", kickstart="kick.rom"))
    b.spec.argv = ["/usr/bin/mame"]
    b.spec.virtual_display = virtual
    proc = tmp_path / "proc"
    proc.mkdir()
    for pid, name in [(10, "wrapper"), (11, "helper"), (12, "fs-uae"), (13, "mame"), (14, "mame")]:
        entry = proc / str(pid)
        entry.mkdir()
        (entry / "comm").write_text(name)
        (entry / "stat").write_text(f"{pid} ({name}) S 1 {20 if pid == 14 else 10}")
    original = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda p: original(proc if p == Path("/proc") else p))
    monkeypatch.setattr(os, "getpgid", lambda pid: 20 if pid == 14 else 10)
    assert b._probe_candidates(10) == [12, 13, 10, 11]
    assert b._probe_candidates(13) == [12, 13, 10, 11]


def test_probe_virtual_display_uses_emulator_pid_file(tmp_path, monkeypatch):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, virtual_display=True, probe=ProbeSpec(kind="mac68k", ram_bytes=65536))
    (tmp_path / "process.pid").write_text("123")
    (tmp_path / "process.emulator.pid").write_text(str(os.getpid()))
    monkeypatch.setattr(b, "_probe_candidates", lambda leader: [leader])

    def probe(spec, pid, state):
        assert pid == os.getpid()
        detail = {"status": "ok", "alive": None}
        state["detail"] = detail
        return None, detail

    monkeypatch.setattr("vmctl_core.backends.process.probe", probe)
    assert b.guest_tasks() == {"status": "ok", "alive": None}
    assert not b.guest_ping()


@pytest.mark.parametrize("virtual", [False, True])
def test_probe_finds_wrapped_emulator_descendants_in_new_groups(tmp_path, monkeypatch, virtual):
    from vmctl_core.backends import ProbeSpec

    b = make(tmp_path, virtual_display=virtual, probe=ProbeSpec(kind="amiga", kickstart="kick.rom"))
    b.spec.argv = ["/scripts/amiga-run.sh"]
    proc = tmp_path / "proc"
    proc.mkdir()
    for pid, parent, group, comm in [
        (12, 11, 12, "fs-uae"),  # grandchild starts a new session
        (11, 10, 11, "nested ) wrapper"),
        (10, 1, 5, "bash"),
        (5, 1, 5, "Xvfb"),
        (14, 5, 5, "helper"),
        (13, 1, 99, "fs-uae"),  # unrelated emulator must not be probed
    ]:
        entry = proc / str(pid)
        entry.mkdir()
        (entry / "comm").write_text(comm)
        (entry / "stat").write_text(f"{pid} ({comm}) S {parent} {group}")
    original = Path.iterdir
    monkeypatch.setattr(Path, "iterdir", lambda p: original(proc if p == Path("/proc") else p))
    monkeypatch.setattr(os, "getpgid", lambda _: 5)
    monkeypatch.setattr(b, "_pid", lambda: 10)
    assert b._probe_candidates(10) == [12, 5, 10, 11, 14]
    calls = []

    def probe(spec, pid, state):
        calls.append(pid)
        assert pid == 12
        return True, {"status": "ok"}

    monkeypatch.setattr("vmctl_core.backends.process.probe", probe)
    assert b.guest_ping()
    assert calls == [12]
