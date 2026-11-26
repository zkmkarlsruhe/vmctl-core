"""ppc/mac99 tap: per-project bridge + bridge-isolated port (two Tiger clones of one golden
share a computer name; Bonjour between them pops a "name in use" modal over the artwork)."""

from __future__ import annotations

import json
import types

import vmctl_core.clone as clone_mod
from vmctl_core.backends.libvirt_backend import LibvirtBackend
from vmctl_core.clone import _tap_ready, create_ppc_tap


def _ns(rc=0, stdout="", stderr=""):
    return types.SimpleNamespace(returncode=rc, stdout=stdout, stderr=stderr)


def _probe(monkeypatch, out):
    monkeypatch.setattr(clone_mod, "_run", lambda cmd: _ns(0, stdout=out))


def test_tap_ready_requires_right_bridge_and_isolation(monkeypatch):
    ok = "9: os9a: <BROADCAST,UP,LOWER_UP> mtu 1500 master rvmc-p10 state UP bridge_slave isolated on"
    _probe(monkeypatch, ok)
    assert _tap_ready("os9a", "rvmc-p10")
    assert not _tap_ready("os9a", "rvmc-p1")  # prefix of rvmc-p10 must not match
    assert not _tap_ready("os9a", "virbr0")  # legacy bridge -> must be re-plumbed
    _probe(monkeypatch, ok.replace("isolated on", "isolated off"))
    assert not _tap_ready("os9a", "rvmc-p10")


def test_create_ppc_tap_enslaves_to_given_bridge_and_isolates(monkeypatch):
    calls: list[list[str]] = []
    state = {"bridge": "virbr0", "iso": False}

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:5] == ["ip", "-d", "-o", "link", "show"]:
            iso = "on" if state["iso"] else "off"
            return _ns(0, stdout=f"9: os9b: <UP,LOWER_UP> master {state['bridge']} isolated {iso}")
        if "master" in cmd:
            state["bridge"] = cmd[-1]
        if "isolated" in cmd:
            state["iso"] = True
        return _ns(0)

    monkeypatch.setattr(clone_mod, "_run", fake_run)
    create_ppc_tap("os9b", bridge="rvmc-p30")
    # old virbr0 tap is torn down and rebuilt on the project bridge, isolated
    assert ["sudo", "ip", "link", "del", "os9b"] in calls
    assert ["sudo", "ip", "link", "set", "os9b", "master", "rvmc-p30"] in calls
    assert [
        "sudo",
        "ip",
        "link",
        "set",
        "dev",
        "os9b",
        "type",
        "bridge_slave",
        "isolated",
        "on",
    ] in calls


def test_ppc_lease_read_from_tap_bridge_status(tmp_path, monkeypatch):
    (tmp_path / "virbr0.status").write_text(
        json.dumps([{"mac-address": "52:54:00:aa:bb:cc", "ip-address": "192.168.122.9"}])
    )
    (tmp_path / "rvmc-p30.status").write_text(
        json.dumps([{"mac-address": "52:54:00:aa:bb:cc", "ip-address": "10.177.3.42"}])
    )
    be = LibvirtBackend("rvmc-test-abc123")
    monkeypatch.setattr(be, "DNSMASQ_STATUS", str(tmp_path / "virbr0.status"))
    monkeypatch.setattr(be, "_ppc_tap", lambda: "os9b")
    monkeypatch.setattr(
        "vmctl_core.backends.libvirt_backend.subprocess.run",
        lambda *a, **k: _ns(0, stdout="9: os9b: <UP> mtu 1500 master rvmc-p30 state UP"),
    )
    assert be._ip_from_dnsmasq(["52:54:00:aa:bb:cc"]) == "10.177.3.42"
    # no tap master readable -> legacy virbr0 DB
    monkeypatch.setattr(be, "_ppc_tap", lambda: None)
    assert be._ip_from_dnsmasq(["52:54:00:aa:bb:cc"]) == "192.168.122.9"
