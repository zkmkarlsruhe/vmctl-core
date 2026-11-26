"""recent() dissects only the tail of a growing pcap and keeps whole-file numbering."""

from __future__ import annotations

import struct
import types
from pathlib import Path

from vmctl_core import capture

_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)


def _rec(i: int, size: int = 60) -> bytes:
    return struct.pack("<IIII", 1000 + i, 500_000, size, size) + bytes([i % 256]) * size


def _fake_tshark(seen: list[int]):
    """Stands in for `tshark -r <file> -T fields`: one row per record, numbered and timed
    relative to the first record of the file it was given (as tshark does)."""

    def run(cmd, **_kw):
        path = cmd[cmd.index("-r") + 1]
        data = Path(path).read_bytes()
        seen.append(len(data))
        rows, off, t0 = [], 24, None
        while off + 16 <= len(data):
            sec, usec, incl, _ = struct.unpack("<IIII", data[off : off + 16])
            t = sec + usec * 1e-6
            t0 = t if t0 is None else t0
            rows.append(f"{len(rows) + 1}\t{t - t0:.9f}\t10.0.0.1\t10.0.0.2\tUDP\t{incl}\tx")
            off += 16 + incl
        return types.SimpleNamespace(stdout="\n".join(rows), stderr="", returncode=0)

    return run


def test_recent_reads_only_the_tail_and_shifts_numbers(tmp_path, monkeypatch):
    seen: list[int] = []
    monkeypatch.setattr(capture.subprocess, "run", _fake_tshark(seen))
    mon = capture.NetworkMonitor(tmp_path)
    pcap = mon.pcap_path("i1")
    pcap.write_bytes(_GLOBAL + b"".join(_rec(i) for i in range(300)) + _rec(300)[:30])

    rows = mon.recent("i1", 100)
    assert [r["no"] for r in rows] == [str(n) for n in range(201, 301)]
    assert rows[0]["time"] == f"{200.0:.9f}"
    assert seen[-1] == 24 + 100 * 76  # tshark saw 100 records, not the 300 (+ partial one)

    # appended packets are picked up incrementally; the partial record completes
    with pcap.open("r+b") as f:
        f.truncate(24 + 300 * 76)
        f.seek(0, 2)
        f.write(b"".join(_rec(i) for i in range(300, 310)))
    rows = mon.recent("i1", 5)
    assert [r["no"] for r in rows] == ["306", "307", "308", "309", "310"]
    assert rows[-1]["time"] == f"{309.0:.9f}"


def test_recent_resets_on_a_new_capture(tmp_path, monkeypatch):
    monkeypatch.setattr(capture.subprocess, "run", _fake_tshark([]))
    mon = capture.NetworkMonitor(tmp_path)
    pcap = mon.pcap_path("i1")
    pcap.write_bytes(_GLOBAL + b"".join(_rec(i) for i in range(50)))
    assert mon.recent("i1", 10)[-1]["no"] == "50"
    pcap.write_bytes(_GLOBAL + b"".join(_rec(i + 7) for i in range(3)))  # restart truncates
    assert [r["no"] for r in mon.recent("i1", 10)] == ["1", "2", "3"]


def test_recent_falls_back_to_full_read_for_non_pcap(tmp_path, monkeypatch):
    calls: list[list[str]] = []

    def run(cmd, **_kw):
        calls.append(cmd)
        return types.SimpleNamespace(stdout="1\t0.0\ta\tb\tUDP\t60\tx", stderr="", returncode=0)

    monkeypatch.setattr(capture.subprocess, "run", run)
    mon = capture.NetworkMonitor(tmp_path)
    mon.pcap_path("i1").write_bytes(b"\x0a\x0d\x0d\x0a" + bytes(60))  # pcapng
    assert mon.recent("i1", 10)[0]["no"] == "1"
    assert calls[0][calls[0].index("-r") + 1] == str(mon.pcap_path("i1"))
    assert mon.recent("i1", 0) == []
