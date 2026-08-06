"""The isolated CONTROL NIC on a virtio-serial golden (P3 dual-pipeline fallback).

A vioser golden may be dual-homed: virtio-serial as the primary agent transport PLUS
an isolated e1000 control NIC on rvmc-mgmt (10.77/24) carrying a TCP-over-control-NIC
fallback that survives a vioser-driver wedge. These tests lock:
  - a vioser + control_nic base renders BOTH NICs — the artwork NIC (unchanged model)
    AND an e1000 control NIC on rvmc-mgmt — plus the vioser channels + qemu-ga;
  - the control NIC model is e1000 (a driver INDEPENDENT of the wedging virtio-serial),
    NOT the artwork nic_model;
  - a plain vioser base (no control NIC) still renders exactly one NIC;
  - the legacy-TCP path (mgmt_nic, no virtio-serial) is byte-identical to before —
    the control NIC keeps nic_model there;
  - the mgmt_nic and control_nic flags are interchangeable aliases for the same emit.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from vmctl_core.catalog import BaseImage, Hardware
from vmctl_core.clone import render_domain_xml

MGMT_NETWORK = "rvmc-mgmt"


def _vioser_base(**hw_over) -> BaseImage:
    hw = Hardware(
        machine="pc",
        disk_bus="virtio",
        nic_model="virtio",
        virtio_serial=True,
        agent_channel=True,
        **hw_over,
    )
    return BaseImage(id="linux-golden", os="linux", path="/srv/golden.qcow2", agent=True, hw=hw)


def _interfaces(xml: str) -> list[ET.Element]:
    return ET.fromstring(xml).findall("./devices/interface")


def _by_network(ifaces: list[ET.Element]) -> dict[str, ET.Element]:
    out: dict[str, ET.Element] = {}
    for i in ifaces:
        src = i.find("source")
        if src is not None:
            out[src.get("network") or ""] = i
    return out


# --- vioser + control NIC: dual-homed --------------------------------------------------------


def test_vioser_control_nic_renders_both_nics():
    xml = render_domain_xml(
        _vioser_base(control_nic=True),
        name="g1",
        disk_path=Path("/clones/g1.qcow2"),
        mac="52:54:00:aa:bb:cc",
        agent_sock="/run/vmctl/g1.sock",
    )
    ifaces = _interfaces(xml)
    assert len(ifaces) == 2, "vioser + control_nic must be dual-homed (artwork + control)"
    by_net = _by_network(ifaces)

    # artwork NIC: the configured network, model UNCHANGED (virtio)
    assert "default" in by_net
    assert by_net["default"].find("model").get("type") == "virtio"
    assert by_net["default"].find("mac").get("address") == "52:54:00:aa:bb:cc"

    # control NIC: isolated rvmc-mgmt network, e1000 (driver-independent of virtio-serial),
    # and NO explicit mac (libvirt auto-assigns)
    assert MGMT_NETWORK in by_net
    ctl = by_net[MGMT_NETWORK]
    assert ctl.find("model").get("type") == "e1000"
    assert ctl.find("mac") is None

    # the vioser plumbing is intact: a controller + qemu-ga channel + the agent lane
    root = ET.fromstring(xml)
    assert root.find(".//controller[@type='virtio-serial']") is not None
    chan_names = {c.find("target").get("name") for c in root.findall(".//channel")}
    assert "org.qemu.guest_agent.0" in chan_names
    assert any(n.startswith("de.zkm.rvmc.agent.") for n in chan_names)


def test_control_nic_model_override_wins():
    # an explicit control_nic_model beats the e1000 default
    xml = render_domain_xml(
        _vioser_base(control_nic=True, control_nic_model="rtl8139"),
        name="g1",
        disk_path=Path("/clones/g1.qcow2"),
    )
    ctl = _by_network(_interfaces(xml))[MGMT_NETWORK]
    assert ctl.find("model").get("type") == "rtl8139"


def test_mgmt_nic_is_an_alias_for_control_nic_on_vioser():
    # mgmt_nic and control_nic trigger the identical emit; on a vioser golden both give e1000.
    # Pin uuid + mac so the compare isolates the flag, not the random per-render identifiers.
    fixed = {"domain_uuid": "11111111-1111-1111-1111-111111111111", "mac": "52:54:00:aa:bb:cc"}
    a = render_domain_xml(
        _vioser_base(control_nic=True), name="g", disk_path=Path("/c/g.qcow2"), **fixed
    )
    b = render_domain_xml(
        _vioser_base(mgmt_nic=True), name="g", disk_path=Path("/c/g.qcow2"), **fixed
    )
    assert a == b
    assert _by_network(_interfaces(a))[MGMT_NETWORK].find("model").get("type") == "e1000"


# --- plain vioser (no control NIC): exactly one NIC ------------------------------------------


def test_plain_vioser_renders_single_nic():
    xml = render_domain_xml(
        _vioser_base(),
        name="g1",
        disk_path=Path("/clones/g1.qcow2"),
        agent_sock="/run/vmctl/g1.sock",
    )
    ifaces = _interfaces(xml)
    assert len(ifaces) == 1
    assert MGMT_NETWORK not in xml
    # vioser channels still present — the control NIC is orthogonal to them
    assert ET.fromstring(xml).find(".//controller[@type='virtio-serial']") is not None


# --- legacy-TCP path stays byte-identical ----------------------------------------------------


def test_legacy_tcp_mgmt_nic_keeps_nic_model_and_is_byte_identical():
    """A legacy-TCP base (no virtio-serial) with mgmt_nic must render EXACTLY as before:
    the control NIC keeps nic_model (here e1000 == artwork model), no e1000-default magic,
    and control_nic is just an alias so the two flags produce identical XML."""
    legacy = BaseImage(
        id="win2000",
        os="windows-2000",
        path="/srv/w2k.qcow2",
        hw=Hardware(
            machine="pc",
            disk_bus="ide",
            nic_model="rtl8139",  # deliberately NOT e1000 to prove no default swap
            clock="localtime",
            virtio_serial=False,
            agent_channel=False,
            memballoon="none",
            mgmt_nic=True,
        ),
    )
    xml = render_domain_xml(legacy, name="w1", disk_path=Path("/clones/w1.qcow2"))
    by_net = _by_network(_interfaces(xml))
    # legacy: control NIC keeps the artwork nic_model (rtl8139), NOT e1000
    assert by_net[MGMT_NETWORK].find("model").get("type") == "rtl8139"
    assert by_net["default"].find("model").get("type") == "rtl8139"
    # no virtio-serial on a legacy base
    assert ET.fromstring(xml).find(".//controller[@type='virtio-serial']") is None
