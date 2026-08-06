"""control_ip() vs artwork_ip(): the codex split-brain guard.

A dual-homed guest (isolated control NIC on 10.77/24 + an artwork NIC) must expose BOTH
identities separately — the agent transport dials the control IP, the data plane keys on
the artwork IP — so the mgmt NIC never leaks into source-IP->project mapping / dnsmasq /
router decisions. A single-NIC guest reports the same lease for both.
"""

from __future__ import annotations

from vmctl_core.backends.libvirt_backend import LibvirtBackend


def _backend(leases, mgmt):
    b = LibvirtBackend("d")
    b._leases = lambda: list(leases)  # type: ignore[method-assign]
    b._has_mgmt_nic = lambda: mgmt  # type: ignore[method-assign]
    return b


def test_single_nic_control_equals_artwork():
    b = _backend(["192.168.122.50"], mgmt=False)
    assert b.control_ip() == "192.168.122.50"
    assert b.artwork_ip() == "192.168.122.50"


def test_dual_homed_split():
    # discovery order artwork-first to prove the split isn't order-luck
    b = _backend(["192.168.122.50", "10.77.0.9"], mgmt=True)
    assert b.control_ip() == "10.77.0.9"  # mgmt subnet -> control
    assert b.artwork_ip() == "192.168.122.50"  # non-mgmt -> artwork


def test_control_none_until_mgmt_lease_up():
    # mgmt NIC declared but only the artwork lease is visible yet
    b = _backend(["192.168.122.50"], mgmt=True)
    assert b.control_ip() is None  # never leak the artwork IP as control
    assert b.artwork_ip() == "192.168.122.50"


def test_artwork_none_when_only_mgmt_lease():
    b = _backend(["10.77.0.9"], mgmt=True)
    assert b.control_ip() == "10.77.0.9"
    assert b.artwork_ip() is None


def test_no_leases_both_none():
    b = _backend([], mgmt=True)
    assert b.control_ip() is None
    assert b.artwork_ip() is None
