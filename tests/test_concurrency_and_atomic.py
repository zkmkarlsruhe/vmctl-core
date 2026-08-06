"""Regression coverage for the 2026-07-25 debug-pass fixes in the shared primitives.

- ``Registry`` mutations are now guarded by a reentrant lock (they run concurrently from the
  controllers' FastAPI threadpool; without it two mutate+save pairs interleave and the later
  os.replace writes a snapshot missing the other's change — a silent lost update).
- ``NetworkMonitor.start`` now takes a per-instance lock so two concurrent starts for one instance
  can't both pass the is_capturing() check and exec two tcpdumps onto the same pcap.
- ``write_text_atomic`` is now used for ``drive.yaml`` and fsyncs the parent dir; a failed write
  leaves the previous file intact rather than a torn one.
"""

import subprocess
import threading

import pytest

from vmctl_core import atomicio
from vmctl_core.capture import NetworkMonitor
from vmctl_core.drive import ArtworkDrive
from vmctl_core.instance import VMInstance
from vmctl_core.project import Registry

# --- Registry lock: no lost updates under concurrent mutation ----------------------------------


def _mk_instance(pid: str, iid: str) -> VMInstance:
    return VMInstance(
        id=iid,
        project_id=pid,
        base_id="win7",
        domain_name=f"d-{iid}",
        overlay_path=f"/tmp/{iid}.qcow2",
        xml_path=f"/tmp/{iid}.xml",
    )


def test_registry_concurrent_add_instance_no_lost_update(tmp_path):
    reg = Registry(tmp_path / "state")
    reg.create_project("p")
    n_threads, per_thread = 8, 25
    barrier = threading.Barrier(n_threads)

    def worker(t: int):
        barrier.wait()  # maximise overlap
        for j in range(per_thread):
            reg.add_instance(_mk_instance("p", f"i{t}-{j}"))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    expected = n_threads * per_thread
    assert len(reg.list_instances("p")) == expected  # nothing dropped in memory
    # …and the ON-DISK registry agrees (the lost-update bug shows as a short reload)
    reloaded = Registry(tmp_path / "state")
    assert len(reloaded.list_instances("p")) == expected


def test_registry_read_during_write_does_not_raise(tmp_path):
    # A read that iterates the shared dict while a writer mutates it must not raise
    # "dict changed size during iteration" — the lock serialises them.
    reg = Registry(tmp_path / "state")
    reg.create_project("p")
    stop = threading.Event()
    errors: list[Exception] = []

    # Writer is BOUNDED: the getters now deep-copy their return (so a caller can't mutate
    # registry state in place), which makes each list_instances() O(n). An unbounded writer
    # would let the instance count — and thus every read and every full-file save() — grow
    # without limit while the slower reader runs, an O(n^2) blow-up. A fixed write count keeps
    # the concurrent-access window (reads iterate the dict while writes mutate it) without the
    # runaway; the reader spins until the writer signals done.
    def writer():
        for i in range(300):
            reg.add_instance(_mk_instance("p", f"w{i}"))
        stop.set()

    def reader():
        try:
            while not stop.is_set():
                reg.list_instances()
                reg.list_instances("p")
        except Exception as e:  # pragma: no cover - only on a regression
            errors.append(e)

    w = threading.Thread(target=writer)
    r = threading.Thread(target=reader)
    w.start()
    r.start()
    w.join()
    r.join()
    assert not errors, errors
    assert len(reg.list_instances("p")) == 300


# --- Registry getters return deep copies (a caller can't mutate registry state in place) -------


def test_getters_return_deep_copies(tmp_path):
    reg = Registry(tmp_path / "state")
    reg.create_project("p")
    reg.add_instance(_mk_instance("p", "i1"))

    # Mutating what a getter hands back must NOT reach into registry state — otherwise a caller
    # edits shared state outside the lock and re-introduces the race the lock is there to prevent.
    proj = reg.get_project("p")
    proj.notes = "tampered"
    proj.instances["i1"].domain_name = "hijacked"
    assert reg.get_project("p").notes == ""
    assert reg.get_instance("i1").domain_name == "d-i1"

    inst = reg.get_instance("i1")
    inst.domain_name = "hijacked-again"
    assert reg.get_instance("i1").domain_name == "d-i1"

    for p in reg.list_projects():
        p.notes = "x"
        p.instances.clear()
    for i in reg.list_instances():
        i.domain_name = "y"
    # registry state is intact after mutating every listed copy
    assert reg.get_project("p").notes == ""
    assert len(reg.list_instances("p")) == 1
    assert reg.get_instance("i1").domain_name == "d-i1"


# --- NetworkMonitor: no double-spawn for one instance ------------------------------------------


class _FakePopen:
    spawns = 0
    lock = threading.Lock()

    def __init__(self, *_a, **_k):
        with _FakePopen.lock:
            _FakePopen.spawns += 1
        # simulate spawn latency so two unsynchronised starts would overlap
        import time

        time.sleep(0.05)

    def poll(self):
        return None  # "still running"

    def wait(self, timeout=None):
        return 0

    def kill(self):
        return None


def test_concurrent_capture_start_spawns_one_tcpdump(tmp_path, monkeypatch):
    _FakePopen.spawns = 0
    monkeypatch.setattr(subprocess, "Popen", _FakePopen)
    mon = NetworkMonitor(tmp_path)
    barrier = threading.Barrier(2)

    def start():
        barrier.wait()
        mon.start("vm1", tap="tap0")

    a = threading.Thread(target=start)
    b = threading.Thread(target=start)
    a.start()
    b.start()
    a.join()
    b.join()

    assert _FakePopen.spawns == 1  # the per-instance lock collapsed the second start
    assert mon.is_capturing("vm1")


# --- atomic writes: a failed write keeps the previous file intact ------------------------------


def test_drive_save_is_atomic_on_failure(tmp_path, monkeypatch):
    d = ArtworkDrive.create(tmp_path, "aw", title="Good")
    d.save(d.load())  # a known-good manifest on disk
    good = d.manifest_path.read_text()

    # Simulate a crash during the replace step of the NEXT save.
    real_replace = atomicio.os.replace

    def boom(src, dst):
        raise OSError("simulated crash mid-rename")

    monkeypatch.setattr(atomicio.os, "replace", boom)
    m = d.load()
    m.stage = "workbench"
    with pytest.raises(OSError):
        d.save(m)
    monkeypatch.setattr(atomicio.os, "replace", real_replace)

    # The previous manifest is intact and still parses — no torn file bricked the drive.
    assert d.manifest_path.read_text() == good
    assert d.load().stage == "intake"
    # and no stray temp file was left behind
    assert not list(tmp_path.glob("aw/**/.drive.yaml*.tmp"))


def test_atomic_write_roundtrip_and_no_temp_left(tmp_path):
    p = tmp_path / "nested" / "f.txt"
    atomicio.write_text_atomic(p, "payload")
    assert p.read_text() == "payload"
    assert not list(p.parent.glob(".f.txt*.tmp"))  # temp cleaned up / renamed
