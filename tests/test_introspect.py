"""Synthetic guest RAM only: no emulator, ROM download, or ptrace permission required."""

import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import ValidationError

from vmctl_core.backends import ProbeSpec, ProcessSpec
from vmctl_core.introspect import amiga as a
from vmctl_core.introspect import liveness
from vmctl_core.introspect import mac68k as m
from vmctl_core.introspect.memory import FakeMemory, ProcMemory, Unreadable

EXEC, FIRST_HEADER, SECOND_HEADER = 0x1000, 0x500, 0x200000
PROCESS, READY, WAIT, PORT = 0x200100, 0x3000, 0x3200, 0x4000
COMMAND = "dh0:orpheus/oc/proj2"
HOST_ONE, HOST_TWO, HOST_ROM = 0x10000000, 0x30000000, 0x50000000


@pytest.fixture
def amiga_image():
    first, second = bytearray(0x10000), bytearray(0x10000)
    rom = bytearray(b"\xff" * 0x2000)
    rom[0x800:0x80D] = b"exec.library\0"
    rom[0x1000:0x1100] = bytes(range(256))

    def put(addr, data):
        bank, offset = (second, addr - 0x200000) if addr >= 0x200000 else (first, addr)
        bank[offset : offset + len(data)] = data

    def long(addr, value):
        put(addr, value.to_bytes(4, "big"))

    def nodes(head, entries):
        long(head, entries[0] if entries else head + 4)
        long(head + 4, 0)
        long(head + 8, entries[-1] if entries else head)
        for index, node in enumerate(entries):
            long(node, entries[index + 1] if index + 1 < len(entries) else head + 4)
            long(node + 4, entries[index - 1] if index else head)

    # Literal NDK offsets make the fixture independent of implementation constants.
    put(EXEC + 8, b"\x09")
    long(EXEC + 10, 0x1000000 - len(rom) + 0x800)
    long(EXEC + 38, EXEC ^ 0xFFFFFFFF)
    put(EXEC + 0x212, b"\x32")
    long(EXEC + 276, PROCESS)
    long(EXEC + 280, 123)
    long(EXEC + 284, 456)
    nodes(EXEC + 322, [FIRST_HEADER, SECOND_HEADER])
    for header, lower, upper in [
        (FIRST_HEADER, 0x600, 0x10000),
        (SECOND_HEADER, 0x200040, 0x210000),
    ]:
        put(header + 8, b"\x0a")
        long(header + 20, lower)
        long(header + 24, upper)
        long(header + 28, 0x100)
    nodes(EXEC + 350, [])
    nodes(EXEC + 378, [])
    nodes(EXEC + 392, [PORT])
    nodes(EXEC + 406, [READY])
    nodes(EXEC + 420, [WAIT])
    for task, name, state, kind in [
        (PROCESS, "Shell", 2, 13),
        (READY, "ready", 3, 1),
        (WAIT, "wait", 4, 1),
    ]:
        put(task + 8, bytes([kind, 0xFF]))
        long(task + 10, task + 0xC0)
        put(task + 15, bytes([state]))
        put(task + 0xC0, name.encode() + b"\0")
    long(PROCESS + 172, 0x200400 >> 2)
    long(0x200400 + 16, 0x200500 >> 2)
    put(0x200500, bytes([len(COMMAND)]) + COMMAND.encode())
    long(PORT + 10, PORT + 0x40)
    put(PORT + 0x40, b"vmctl.heartbeat\0")
    long(PORT + 34, 42)
    mem = FakeMemory(
        {
            (HOST_ONE, HOST_ONE + len(first)): first,
            (HOST_TWO, HOST_TWO + len(second)): second,
            (HOST_ROM, HOST_ROM + len(rom)): bytes(rom),
        }
    )
    return mem, bytes(rom), put, long


def attached_amiga(image):
    mem, rom, _, _ = image
    view = a.AmigaView(mem, rom)
    view.attach()
    return view


def test_amiga_discovers_two_banks_and_process_cli(amiga_image):
    view = attached_amiga(amiga_image)
    sample = view.sample()
    assert view.exec == EXEC
    assert any(lo == 0 and delta == HOST_ONE for lo, _, delta in view.banks)
    assert any(lo == 0x200000 and delta == HOST_TWO - 0x200000 for lo, _, delta in view.banks)
    assert (sample.dispatch, sample.idle, sample.heartbeat) == (456, 123, 42)
    assert sample.status == "ok"
    assert sample.tasks == [
        a.Task("Shell", "run", "process", -1, COMMAND),
        a.Task("ready", "ready", "task", -1),
        a.Task("wait", "wait", "task", -1),
    ]
    assert sample.ports == ["vmctl.heartbeat"]


def test_amiga_retries_torn_task_list(amiga_image, monkeypatch):
    view = attached_amiga(amiga_image)
    mem = amiga_image[0]
    read = mem.read
    reads = 0

    def torn(addr, size):
        nonlocal reads
        if addr == HOST_ONE + READY + 4:
            reads += 1
            if reads == 1:
                return b"\0" * size
        return read(addr, size)

    monkeypatch.setattr(mem, "read", torn)
    assert view.sample().status == "ok"
    assert reads == 2


def test_amiga_retries_torn_memlist(amiga_image, monkeypatch):
    mem = amiga_image[0]
    read = mem.read
    reads = 0

    def torn(addr, size):
        nonlocal reads
        if addr == HOST_ONE + FIRST_HEADER + 4:
            reads += 1
            if reads == 1:
                return b"\0" * size
        return read(addr, size)

    monkeypatch.setattr(mem, "read", torn)
    assert attached_amiga(amiga_image).sample().status == "ok"
    assert reads >= 2


@pytest.mark.parametrize("fault", ["pred", "cycle", "false_tail", "bounds", "short_read", "io"])
def test_amiga_bad_reads_are_unreadable(amiga_image, monkeypatch, fault):
    view = attached_amiga(amiga_image)
    mem, _, _, long = amiga_image
    monkeypatch.setattr(a.time, "sleep", lambda _: None)
    if fault == "pred":
        long(READY + 4, 123)
    elif fault == "cycle":
        long(READY, READY)
    elif fault == "false_tail":
        long(READY, 0x4500)
        long(0x4500, 0)
        long(0x4504, READY)
    elif fault == "bounds":
        long(EXEC + 276, 0x20FFF0)
    else:

        def bad_read(addr, size):
            if fault == "io":
                raise OSError("emulator exited")
            return b""

        monkeypatch.setattr(mem, "read", bad_read)
    sample = view.sample()
    assert sample.status == "unreadable"
    assert sample.error
    assert sample.dispatch is None


def test_amiga_bounds_and_missing_heartbeat(amiga_image):
    view = attached_amiga(amiga_image)
    _, _, put, _ = amiga_image
    with pytest.raises(Unreadable):
        view.get(0x20FFFF, 4)
    put(PORT + 0x40, b"other\0")
    assert view.sample().heartbeat is None


def test_missing_or_invalid_execbase(amiga_image):
    mem, rom, _put, long = amiga_image
    long(EXEC + 38, 0)
    with pytest.raises(Unreadable, match="ExecBase"):
        a.AmigaView(mem, rom).attach()
    with pytest.raises(Unreadable, match="Kickstart"):
        a.AmigaView(mem, b"").attach()


@pytest.fixture
def mac_image():
    ram_size, header = 0x10000, 0x30
    guest = bytearray(ram_size)
    guest[0x2AE:0x2B2] = (0x40800000).to_bytes(4, "big")
    guest[0x16A:0x16E] = (0x12345678).to_bytes(4, "big")
    guest[0x15A:0x15C] = (0x755).to_bytes(2, "big")
    guest[0x910:0x917] = b"\x06Finder"
    raw = b"".join(
        guest[i : i + 4][::-1] if sys.byteorder == "little" else guest[i : i + 4]
        for i in range(0, ram_size, 4)
    )
    host = 0x10000000
    mem = FakeMemory({(host, host + ram_size + header): b"\0" * header + raw})
    return mem, ram_size, host + header


def test_mac_host_words_and_unaligned_globals(mac_image):
    mem, ram_size, base = mac_image
    view = m.MacView(mem, ram_size)
    view.attach()
    assert view.base == base
    sample = view.sample()
    assert (sample.ticks, sample.cur_app, sample.sysversion) == (0x12345678, "Finder", "0x755")
    assert sample.status == "ok"
    with pytest.raises(Unreadable):
        view.get(ram_size - 1, 2)


def test_mac_missing_ram_and_unreadable_sample(mac_image, monkeypatch):
    mem, ram_size, _ = mac_image
    view = m.MacView(mem, ram_size)
    assert view.sample().status == "unreadable"
    view.attach()
    monkeypatch.setattr(mem, "read", lambda *args: b"")
    assert view.sample().status == "unreadable"
    with pytest.raises(Unreadable, match="not found"):
        view.attach()


@pytest.fixture
def probe_memory(monkeypatch):
    class FakeProc(FakeMemory):
        identity = (123, "start")
        closed = 0
        ranges_source: ClassVar[dict] = {}

        def __init__(self, pid):
            super().__init__(self.ranges_source)
            self.identity = (pid, "start")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            type(self).closed += 1

    monkeypatch.setattr(liveness, "ProcMemory", FakeProc)
    return FakeProc


def test_liveness_with_real_amiga_view(amiga_image, probe_memory, tmp_path):
    mem, rom, put, long = amiga_image
    probe_memory.ranges_source = mem.ranges
    rom_path = tmp_path / "kick.rom"
    rom_path.write_bytes(rom)
    spec = ProbeSpec(kind="amiga", kickstart="kick.rom", expect=["PROJ2", "shell"])
    spec = spec.model_copy(update={"kickstart": str(rom_path)})
    state = {}
    assert liveness.probe(spec, 123, state)[0] is None
    assert liveness.probe(spec, 123, state)[0] is None
    long(PORT + 34, 43)
    assert liveness.probe(spec, 123, state)[0] is True
    put(0x200500, b"\x05other")
    long(PORT + 34, 44)
    alive, detail = liveness.probe(spec, 123, state)
    assert alive is False
    assert detail["missing"] == ["PROJ2"]
    assert probe_memory.closed == 4


def test_liveness_mac_and_instance_isolation(mac_image, probe_memory, monkeypatch):
    mem, ram_size, _ = mac_image
    probe_memory.ranges_source = mem.ranges
    spec = ProbeSpec(kind="mac68k", ram_bytes=ram_size, expect=["Finder"])
    state, other = {}, {}
    assert liveness.probe(spec, 123, state)[0] is None
    assert liveness.probe(spec, 123, state)[0] is None
    original = m.MacView.sample
    monkeypatch.setattr(m.MacView, "sample", lambda self: replace(original(self), ticks=0x12345679))
    assert liveness.probe(spec, 123, state)[0] is True
    assert liveness.probe(spec, 123, other)[0] is None
    assert liveness.probe(spec, 124, state)[0] is None
    missing = spec.model_copy(update={"expect": ["Other"]})
    assert liveness.probe(missing, 124, state)[0] is None
    monkeypatch.setattr(m.MacView, "sample", lambda self: replace(original(self), ticks=0x12345680))
    assert liveness.probe(missing, 124, state)[0] is False


def test_counter_wrap_reset_expiry_and_source_change(
    amiga_image, probe_memory, tmp_path, monkeypatch
):
    mem, rom, put, long = amiga_image
    probe_memory.ranges_source = mem.ranges
    path = tmp_path / "kick.rom"
    path.write_bytes(rom)
    spec = ProbeSpec(kind="amiga", kickstart="kick.rom").model_copy(update={"kickstart": str(path)})
    now = 100.0
    monkeypatch.setattr(liveness.time, "monotonic", lambda: now)
    state = {}
    long(PORT + 34, 0xFFFFFFFF)
    assert liveness.probe(spec, 123, state)[0] is None
    long(PORT + 34, 0)
    assert liveness.probe(spec, 123, state)[0] is True
    long(PORT + 34, 100)
    assert liveness.probe(spec, 123, state)[0] is True
    long(PORT + 34, 0)
    assert liveness.probe(spec, 123, state)[0] is False
    now += 11
    long(PORT + 34, 1)
    assert liveness.probe(spec, 123, state)[0] is True
    put(PORT + 0x40, b"other\0")
    assert liveness.probe(spec, 123, state)[0] is None
    long(EXEC + 284, 457)
    assert liveness.probe(spec, 123, state)[0] is True


def test_unreadable_probe_reattaches(mac_image, probe_memory, monkeypatch):
    mem, size, _ = mac_image
    probe_memory.ranges_source = mem.ranges
    state = {}
    spec = ProbeSpec(kind="mac68k", ram_bytes=size)
    assert liveness.probe(spec, 1, state)[0] is None
    original = m.MacView.sample
    monkeypatch.setattr(
        m.MacView, "sample", lambda self: m.MacSample(status="unreadable", error="gone")
    )
    alive, detail = liveness.probe(spec, 1, state)
    assert alive is False and detail["status"] == "unreadable"
    assert "view" not in state
    monkeypatch.setattr(m.MacView, "sample", original)
    assert liveness.probe(spec, 1, state)[0] is None


@pytest.mark.parametrize(
    "probe",
    [
        None,
        {"kind": "amiga", "kickstart": "roms/kick.rom", "expect": ["proj2"]},
        {"kind": "mac68k", "ram_bytes": 16 << 20},
    ],
)
def test_spec_roundtrip(probe):
    data = {"argv": ["emulator"]}
    if probe:
        data["probe"] = probe
    spec = ProcessSpec.model_validate(data)
    assert ProcessSpec.model_validate_json(spec.model_dump_json()) == spec
    if probe is None:
        assert spec.probe is None
    else:
        assert spec.probe.max_age_s == 10


@pytest.mark.parametrize(
    "data",
    [
        {"kind": "bad"},
        {"kind": "amiga"},
        {"kind": "amiga", "kickstart": "../kick.rom"},
        {"kind": "amiga", "kickstart": "/kick.rom"},
        {"kind": "mac68k"},
        {"kind": "mac68k", "ram_bytes": 65536, "max_age_s": 0},
    ],
)
def test_invalid_probe_spec(data):
    with pytest.raises(ValidationError):
        ProbeSpec.model_validate(data)


def test_memory_find_boundaries_and_limits(monkeypatch):
    from vmctl_core.introspect import memory

    monkeypatch.setattr(memory, "SCAN_BYTES", 4)
    mem = FakeMemory({(100, 114): b"___abc___abc__"})
    assert mem.find(b"abc") == [103, 109]
    assert mem.find(b"abc", limit=1) == [103]
    assert mem.find(b"") == []
    with pytest.raises(Unreadable):
        mem.read(113, 2)


def test_proc_memory_maps_pread_only_and_close(monkeypatch):
    real_read_text = Path.read_text

    def read_text(path, *args, **kwargs):
        if str(path) == "/proc/123/maps":
            return "1000-2000 rw-p 00000000 00:00 0\n2000-3000 ---p 00000000 00:00 0\n3000-4000 r-xp 00000000 00:00 0 /usr/lib/lib.so\n"
        if str(path) == "/proc/123/stat":
            return "123 (name with ) brackets) S " + " ".join(["0"] * 18 + ["12345"])
        return real_read_text(path, *args, **kwargs)

    calls, closed = [], []
    monkeypatch.setattr(Path, "read_text", read_text)
    monkeypatch.setattr(os, "open", lambda path, flags: calls.append((path, flags)) or 99)
    monkeypatch.setattr(os, "pread", lambda fd, size, addr: b"x" * size)
    monkeypatch.setattr(os, "close", closed.append)
    with ProcMemory(123) as mem:
        assert mem.maps == [(0x1000, 0x2000)]
        assert mem.identity == (123, "12345")
        assert mem.read(0x1000, 4) == b"xxxx"
        with pytest.raises(Unreadable):
            mem.read(0x1FFF, 4)
    mem.close()
    assert calls == [("/proc/123/mem", os.O_RDONLY)]
    assert closed == [99]


def test_amiga_flat_mapping_preserves_uae_area_and_bounds():
    host = 0x10000000
    mem = FakeMemory({(host, host + 0x1000000): bytes(0x1000000)})
    view = a.AmigaView(mem, b"")
    view.banks = [(0, 0x10000, host), (0xF80000, 0x1000000, host)]
    assert view.get(0xF00000, 4) == b"\0" * 4
    with pytest.raises(Unreadable):
        view.get(0xFFFF, 4)  # do not cross a known bank even in a flat mapping
    with pytest.raises(Unreadable):
        view.get(0x1000000, 4)


def test_heartbeat_takes_priority_over_dispatch(amiga_image, probe_memory, tmp_path):
    mem, rom, _, long = amiga_image
    probe_memory.ranges_source = mem.ranges
    path = tmp_path / "kick.rom"
    path.write_bytes(rom)
    spec = ProbeSpec(kind="amiga", kickstart="kick.rom", expect=[COMMAND])
    spec = spec.model_copy(update={"kickstart": str(path)})
    state = {}
    assert liveness.probe(spec, 123, state)[0] is None
    long(EXEC + 284, 999)
    alive, detail = liveness.probe(spec, 123, state)
    assert alive is None
    assert detail["counter"] == "heartbeat"
    assert detail["missing"] == []


def test_memory_permission_errors_propagate(amiga_image, monkeypatch):
    view = attached_amiga(amiga_image)

    def denied(*args):
        raise PermissionError("ptrace denied")

    monkeypatch.setattr(amiga_image[0], "read", denied)
    with pytest.raises(PermissionError):
        amiga_image[0].find(b"needle")
    with pytest.raises(PermissionError):
        view.sample()


def test_probe_permission_failure_clears_baseline(monkeypatch):
    def denied(*args):
        raise PermissionError("ptrace denied")

    monkeypatch.setattr(liveness, "ProcMemory", denied)
    state = {"previous": ("ticks", 10, 1)}
    with pytest.raises(PermissionError):
        liveness.probe(ProbeSpec(kind="mac68k", ram_bytes=65536), 123, state)
    assert state == {}


def test_pid_reuse_warms_up(mac_image, probe_memory, monkeypatch):
    mem, size, _ = mac_image
    probe_memory.ranges_source = mem.ranges
    spec = ProbeSpec(kind="mac68k", ram_bytes=size)
    state = {}
    assert liveness.probe(spec, 1, state)[0] is None
    original = probe_memory.__init__

    def reused(self, pid):
        original(self, pid)
        self.identity = (pid, "new-starttime")

    monkeypatch.setattr(probe_memory, "__init__", reused)
    assert liveness.probe(spec, 1, state)[0] is None


def test_memlist_rejects_bank_outside_host_map(amiga_image, monkeypatch):
    _, _, _, long = amiga_image
    long(SECOND_HEADER + 24, 0x220000)
    monkeypatch.setattr(a, "LIST_RETRIES", 2)
    monkeypatch.setattr(a.time, "sleep", lambda _: None)
    with pytest.raises(Unreadable):
        attached_amiga(amiga_image)


def test_task_list_cap(amiga_image, monkeypatch):
    view = attached_amiga(amiga_image)
    monkeypatch.setattr(a.time, "sleep", lambda _: None)
    with pytest.raises(Unreadable):
        view.nodes(EXEC + 406, limit=0)


@pytest.mark.parametrize(
    "samples",
    [
        [
            (0, 42, None),
            (1, 42, None),
            (2, 43, True),
            (3, 43, True),
            (4, 44, True),
            (5, 44, True),
            (14, 44, True),
            (14.01, 44, False),
            (30, 45, True),
            (60, 46, True),
            (61, 0, False),
            (62, 0, False),
            (63, 1, True),
            (73.01, 1, False),
        ],
        [(0, 42, None), (9.99, 42, None), (10, 42, False), (11, 42, False), (30, 43, True)],
    ],
    ids=["equal-polls-expiry-rare-polls-reset", "warmup-deadline-first-change"],
)
def test_heartbeat_freshness(amiga_image, probe_memory, tmp_path, monkeypatch, samples):
    mem, rom, _, long = amiga_image
    probe_memory.ranges_source = mem.ranges
    path = tmp_path / "kick.rom"
    path.write_bytes(rom)
    spec = ProbeSpec(kind="amiga", kickstart="kick.rom", expect=["proj2"])
    spec = spec.model_copy(update={"kickstart": str(path)})
    now = 0
    monkeypatch.setattr(liveness.time, "monotonic", lambda: now)
    state = {}
    for now, counter, expected in samples:
        long(PORT + 34, counter)
        alive, detail = liveness.probe(spec, 123, state)
        assert alive is expected, (now, counter, detail)


def test_expected_program_required_during_freshness_window(
    amiga_image, probe_memory, tmp_path, monkeypatch
):
    mem, rom, put, long = amiga_image
    probe_memory.ranges_source = mem.ranges
    path = tmp_path / "kick.rom"
    path.write_bytes(rom)
    spec = ProbeSpec(kind="amiga", kickstart="kick.rom", expect=["proj2"])
    spec = spec.model_copy(update={"kickstart": str(path)})
    now = 0
    monkeypatch.setattr(liveness.time, "monotonic", lambda: now)
    state = {}
    assert liveness.probe(spec, 123, state)[0] is None
    now = 1
    long(PORT + 34, 43)
    assert liveness.probe(spec, 123, state)[0] is True
    now = 2
    put(0x200500, b"\x05other")
    alive, detail = liveness.probe(spec, 123, state)
    assert alive is False
    assert detail["missing"] == ["proj2"]
    put(0x200500, bytes([len(COMMAND)]) + COMMAND.encode())
    assert liveness.probe(spec, 123, state)[0] is True
