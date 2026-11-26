"""Capture parsers over real tshark output shapes, plus the start/limit/timeout guards."""

from __future__ import annotations

import subprocess
import types

import pytest

from vmctl_core import capture
from vmctl_core.backends.base import BackendError
from vmctl_core.backends.libvirt_backend import LibvirtBackend
from vmctl_core.project_net import LibvirtNetworks

_CONV_LINE = (
    "192.168.122.10:49153 <-> 93.184.216.34:80         12 8 kB        10 1234 bytes"
    "        22 9 kB     0.000000000         2.5000"
)

_PHS = """\
eth                                      frames:120 bytes:45000
  ip                                     frames:118 bytes:44800
    tcp                                  frames:100 bytes:40000
      http                               frames:12 bytes:9000
      tcp.segments                       frames:30 bytes:20000
        http                             frames:5 bytes:4000
"""

_HDR_CELL = "Host: example.com\\r\\n|User-Agent: Mozilla/4.0\\r\\n|Accept: */*\\r\\n"


def test_conv_totals_reads_the_total_pair():
    tail = _CONV_LINE.split()[_CONV_LINE.split().index("<->") + 2 :]
    assert capture.NetworkMonitor._conv_totals(tail) == (9000, 22)


def test_proto_counts_keeps_max_per_proto(tmp_path, monkeypatch):
    monkeypatch.setattr(
        capture.subprocess, "run", lambda *a, **k: types.SimpleNamespace(stdout=_PHS, returncode=0)
    )
    counts = capture.NetworkMonitor(tmp_path)._proto_counts(tmp_path / "x.pcap")
    assert counts == {"eth": 120, "ip": 118, "tcp": 100, "http": 12, "tcp.segments": 30}


def test_split_headers_strips_crlf_and_aggregator():
    assert capture.NetworkMonitor._split_headers(_HDR_CELL, "|") == [
        "Host: example.com",
        "User-Agent: Mozilla/4.0",
        "Accept: */*",
    ]


def _rows_for(display_filter: str, fields: list[str]) -> list[list[str]]:
    if display_filter == "http.request":
        return [["4", "1.0", "7", "GET", "example.com", "/a", "", "93.184.216.34", "0", _HDR_CELL]]
    if display_filter == "http.response":
        return [
            [
                "7",
                "1.25",
                "4",
                "200",
                "OK",
                "text/html; charset=utf-8",
                "512",
                "",
                "93.184.216.34",
                "0",
                "Content-Type: text/html\\r\\n|X-Cache: HIT\\r\\n",
            ]
        ]
    return []


def test_http_transactions_pairs_response_to_request(tmp_path, monkeypatch):
    mon = capture.NetworkMonitor(tmp_path)
    monkeypatch.setattr(mon, "_tshark_fields", lambda pcap, f, fields, **kw: _rows_for(f, fields))
    txns = mon._http_transactions(tmp_path / "x.pcap", 10, with_bodies=False)
    assert len(txns) == 1
    t = txns[0]
    assert t["request"]["frame"] == 4 and t["request"]["url"] == "http://example.com/a"
    assert t["request"]["headers"][0] == "Host: example.com"
    assert t["response"]["frame"] == 7 and t["response"]["status"] == 200
    assert t["response"]["content_type"] == "text/html"
    assert t["archived"] is True and t["timing"]["elapsed_ms"] == 250.0
    assert mon._http_transactions(tmp_path / "x.pcap", 0, with_bodies=False) == []


def test_recent_count_zero_is_empty(tmp_path, monkeypatch):
    mon = capture.NetworkMonitor(tmp_path)
    mon.pcap_path("i").write_bytes(b"x")
    out = "1\t0.1\ta\tb\tTCP\t60\tinfo\n2\t0.2\ta\tb\tTCP\t60\tinfo\n"
    monkeypatch.setattr(
        capture.subprocess, "run", lambda *a, **k: types.SimpleNamespace(stdout=out, returncode=0)
    )
    assert mon.recent("i", count=0) == []
    assert [r["no"] for r in mon.recent("i", count=1)] == ["2"]


def test_start_raises_with_log_tail_when_tcpdump_exits_at_once(tmp_path, monkeypatch):
    class _Dead:
        returncode = 1

        def __init__(self, argv, stderr=None, **kw):
            stderr.write(b"sudo: a password is required\n")

        def poll(self):
            return 1

    monkeypatch.setattr(capture.subprocess, "Popen", _Dead)
    monkeypatch.setattr(capture.time, "sleep", lambda s: None)
    mon = capture.NetworkMonitor(tmp_path)
    with pytest.raises(RuntimeError, match="a password is required"):
        mon.start("i", "tap0")
    assert not mon.is_capturing("i")
    assert (tmp_path / "i.log").read_text().startswith("sudo:")


def test_summarize_timeout_returns_partial_digest(tmp_path, monkeypatch):
    mon = capture.NetworkMonitor(tmp_path)
    mon.pcap_path("i").write_bytes(b"x")
    monkeypatch.setattr(mon, "_http_transactions", lambda *a, **k: [])

    def boom(*a, **k):
        raise subprocess.TimeoutExpired("tshark", 60)

    monkeypatch.setattr(mon, "_tshark_fields", boom)
    out = mon.summarize("i")
    assert out["pcap"] == "i.pcap" and out["transactions"] == [] and out["dns"] == []
    assert "timed out" in out["error"]


def test_virsh_timeout_is_a_backend_error(monkeypatch):
    def boom(*a, **k):
        raise subprocess.TimeoutExpired("virsh", 30)

    monkeypatch.setattr(subprocess, "run", boom)
    with pytest.raises(BackendError, match="timed out"):
        LibvirtBackend("dom").state()
    with pytest.raises(BackendError, match="timed out"):
        LibvirtNetworks().exists("net")
