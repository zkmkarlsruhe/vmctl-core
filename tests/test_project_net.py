"""Per-project isolated-net derivation + XML (network-isolation hardening).

The virsh lifecycle (`LibvirtNetworks`) is exercised on the box; here we pin the pure,
deterministic half: index→network math, the isolated XML shape (NO <forward>), and the
subnet-membership resolver that maps a destination gateway back to its project.
"""

from __future__ import annotations

import ipaddress
import xml.etree.ElementTree as ET

import pytest

from vmctl_core.project_net import (
    DNSMASQ_NS,
    MAX_INDEX,
    NET_SECOND_OCTET,
    LibvirtNetworks,
    ProjectNet,
    render_network_xml,
)


def test_derivation_is_deterministic_and_indexed():
    pn = ProjectNet.from_index(3)
    assert pn == ProjectNet.from_index(3)  # pure function of the index
    assert pn.name == "rvmc-p3"
    assert pn.bridge == "rvmc-p30"
    assert pn.subnet == f"10.{NET_SECOND_OCTET}.3.0/24"
    assert pn.gateway == f"10.{NET_SECOND_OCTET}.3.1"
    assert pn.netmask == "255.255.255.0"
    assert pn.dhcp_start == f"10.{NET_SECOND_OCTET}.3.2"
    assert pn.dhcp_end == f"10.{NET_SECOND_OCTET}.3.254"


def test_bridge_name_within_ifname_limit():
    # Linux caps interface names at 15 chars; the widest index must still fit.
    assert len(ProjectNet.from_index(MAX_INDEX).bridge) <= 15


def test_distinct_projects_get_distinct_non_overlapping_subnets():
    a, b = ProjectNet.from_index(5), ProjectNet.from_index(6)
    assert a.subnet != b.subnet
    assert not a.network.overlaps(b.network)


def test_index_range_is_enforced():
    with pytest.raises(ValueError):
        ProjectNet.from_index(-1)
    with pytest.raises(ValueError):
        ProjectNet.from_index(MAX_INDEX + 1)


def test_block_avoids_known_routes_on_the_box():
    # The 10.177/16 block must not collide with anything routed on the rvmc host.
    forbidden = [
        ipaddress.ip_network("10.0.0.0/24"),  # home-pve subnet route
        ipaddress.ip_network("10.1.0.0/24"),  # garden-pve subnet route
        ipaddress.ip_network("172.16.0.0/12"),  # docker pool
        ipaddress.ip_network("100.64.0.0/10"),  # tailscale CGNAT
        ipaddress.ip_network("192.168.0.0/16"),  # tailnet-advertised LANs
    ]
    for idx in (0, 1, 77, MAX_INDEX):
        net = ProjectNet.from_index(idx).network
        assert not any(net.overlaps(f) for f in forbidden), idx


def test_xml_is_isolated_no_forward():
    pn = ProjectNet.from_index(7)
    root = ET.fromstring(render_network_xml(pn))
    assert root.tag == "network"
    assert root.findtext("name") == "rvmc-p7"
    assert root.find("bridge").get("name") == "rvmc-p70"
    ip = root.find("ip")
    assert ip.get("address") == pn.gateway
    assert ip.get("netmask") == "255.255.255.0"
    rng = ip.find("dhcp/range")
    assert rng.get("start") == pn.dhcp_start and rng.get("end") == pn.dhcp_end
    # the containment invariant: an isolated net has NO <forward>
    assert root.find("forward") is None
    # DHCP hands out the gateway as default router (overrides libvirt's empty option 3)
    opts = [o.get("value") for o in root.iter(f"{{{DNSMASQ_NS}}}option")]
    assert opts == [f"dhcp-option=3,{pn.gateway}"]


def test_contains_resolves_gateway_to_project():
    pn = ProjectNet.from_index(4)
    assert pn.contains(pn.gateway)
    assert pn.contains(f"10.{NET_SECOND_OCTET}.4.50")
    assert not pn.contains(f"10.{NET_SECOND_OCTET}.5.1")
    assert not pn.contains("not-an-ip")


class _FakeVirsh:
    """Records virsh calls; ``net-dumpxml`` returns ``self.xml`` (what libvirt holds),
    ``net-define`` stores the defined file's content."""

    def __init__(self, xml: str | None) -> None:
        self.xml = xml
        self.calls: list[str] = []

    def __call__(self, *args: str, timeout: float = 30.0, check: bool = True):
        import types

        self.calls.append(args[0])
        out, rc = "", 0
        if args[0] == "net-info":
            rc = 0 if self.xml is not None else 1
            out = "Active:         yes\n"
        elif args[0] == "net-dumpxml":
            out = self.xml or ""
        elif args[0] == "net-define":
            with open(args[1]) as f:
                self.xml = f.read()
        return types.SimpleNamespace(returncode=rc, stdout=out, stderr="")


def _libvirt_dump(xml: str, uuid: str = "0b5c4a5e-1111-2222-3333-444455556666") -> str:
    """What net-dumpxml returns: our XML plus uuid + bridge mac, no comment."""
    root = ET.fromstring(xml)
    u = ET.Element("uuid")
    u.text = uuid
    root.insert(1, u)
    ET.SubElement(root, "mac", address="52:54:00:aa:bb:cc")
    dns = ET.SubElement(root, "dns")
    ET.SubElement(ET.SubElement(dns, "host", ip="10.177.9.1"), "hostname").text = "vmctl.local"
    ET.register_namespace("dnsmasq", DNSMASQ_NS)
    return ET.tostring(root, encoding="unicode")


def _old_xml(pn: ProjectNet) -> str:
    """Pre-router XML (no dnsmasq options) as defined by earlier rvmc versions."""
    root = ET.fromstring(render_network_xml(pn))
    root.remove(root.find(f"{{{DNSMASQ_NS}}}options"))
    return ET.tostring(root, encoding="unicode")


def test_redefine_old_net_destroys_defines_starts_and_keeps_uuid():
    pn = ProjectNet.from_index(9)
    nets = LibvirtNetworks()
    fake = _FakeVirsh(_libvirt_dump(_old_xml(pn)))
    nets._virsh = fake  # type: ignore[method-assign]
    assert nets.redefine(pn) is True
    assert [c for c in fake.calls if c in ("net-define", "net-destroy", "net-start")] == [
        "net-define",
        "net-destroy",
        "net-start",
    ]
    defined = ET.fromstring(fake.xml)
    assert defined.findtext("uuid") == "0b5c4a5e-1111-2222-3333-444455556666"
    assert defined.find("mac").get("address") == "52:54:00:aa:bb:cc"
    assert defined.findtext("dns/host/hostname") == "vmctl.local"
    assert [o.get("value") for o in defined.iter(f"{{{DNSMASQ_NS}}}option")] == [
        f"dhcp-option=3,{pn.gateway}"
    ]


def test_redefine_is_idempotent_when_current():
    pn = ProjectNet.from_index(9)
    nets = LibvirtNetworks()
    fake = _FakeVirsh(_libvirt_dump(render_network_xml(pn)))
    nets._virsh = fake  # type: ignore[method-assign]
    assert nets.redefine(pn) is False
    assert not {"net-define", "net-destroy", "net-start"} & set(fake.calls)


def test_redefine_missing_net_is_noop():
    nets = LibvirtNetworks()
    fake = _FakeVirsh(None)
    nets._virsh = fake  # type: ignore[method-assign]
    assert nets.redefine(ProjectNet.from_index(9)) is False
    assert fake.calls == ["net-info"]


def test_ensure_parallel_defines_once(tmp_path, monkeypatch):
    import threading
    import time

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    pn = ProjectNet.from_index(9)
    nets = LibvirtNetworks()
    fake = _FakeVirsh(None)

    def slow_virsh(*args, **kw):
        if args[0] == "net-define":
            time.sleep(0.05)  # widen the check-then-define window
        return fake(*args, **kw)

    nets._virsh = slow_virsh  # type: ignore[method-assign]
    threads = [threading.Thread(target=nets.ensure, args=(pn,)) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert fake.calls.count("net-define") == 1


def test_ensure_waits_for_lock_held_elsewhere(tmp_path, monkeypatch):
    """A holder outside this call (own fd, as another process has) blocks ensure()."""
    import fcntl
    import threading

    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    pn = ProjectNet.from_index(9)
    nets = LibvirtNetworks()
    fake = _FakeVirsh(None)
    nets._virsh = fake  # type: ignore[method-assign]
    with open(tmp_path / f"vmctl-net-{pn.name}.lock", "w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        t = threading.Thread(target=nets.ensure, args=(pn,))
        t.start()
        t.join(0.2)
        assert t.is_alive() and fake.calls == []
    t.join(5)
    assert not t.is_alive() and fake.calls.count("net-define") == 1
