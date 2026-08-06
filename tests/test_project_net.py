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
    MAX_INDEX,
    NET_SECOND_OCTET,
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
        ipaddress.ip_network("10.77.0.0/24"),  # rvmc-mgmt
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


def test_contains_resolves_gateway_to_project():
    pn = ProjectNet.from_index(4)
    assert pn.contains(pn.gateway)
    assert pn.contains(f"10.{NET_SECOND_OCTET}.4.50")
    assert not pn.contains(f"10.{NET_SECOND_OCTET}.5.1")
    assert not pn.contains("not-an-ip")
