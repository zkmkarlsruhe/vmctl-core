"""ppc/mac99: the guest sees exactly one pointer. `-usb` would re-enable the mac99 machine's
own OHCI, which under via=pmu also auto-adds a RELATIVE usb-mouse that races the usb-tablet
for the active input slot (Tiger cold start: `info mice` showed the mouse active, VNC
absolute clicks were dropped). An explicit OHCI keeps libvirt's usb=off in force."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from vmctl_core.catalog import BaseImage, Hardware
from vmctl_core.clone import render_domain_xml

QNS = "{http://libvirt.org/schemas/domain/qemu/1.0}"


def _args(**hw):
    base = BaseImage(
        id="tiger",
        path="t.qcow2",
        os="mac-os-x-tiger",
        hw=Hardware(arch="ppc", machine="mac99", memory_mb=512, **hw),
    )
    root = ET.fromstring(render_domain_xml(base, name="t1", disk_path=Path("/c/t1.qcow2")))
    return [a.get("value") for a in root.iter(f"{QNS}arg")]


def _devices(args):
    return [args[i + 1] for i, a in enumerate(args) if a == "-device"]


def test_no_usb_flag_explicit_ohci_before_auto_slotted_pci_devices():
    args = _args()
    assert "-usb" not in args
    devs = _devices(args)
    assert devs[0] == "pci-ohci,id=ohci,bus=pci.2,addr=0xd"  # before sungem/VGA keep 0e/0f
    assert devs.index(devs[0]) < [d.split(",")[0] for d in devs].index("sungem")


def test_single_tablet_on_the_ohci():
    devs = _devices(_args())
    assert "usb-tablet,bus=ohci.0" in devs and "usb-kbd,bus=ohci.0" in devs
    assert not any(d.startswith("usb-mouse") for d in devs)


def test_relative_mouse_only_when_tablet_disabled():
    devs = _devices(_args(usb_tablet=False))
    assert "usb-mouse,bus=ohci.0" in devs and not any("usb-tablet" in d for d in devs)


def test_tiger_declares_tablet_gain_and_default_is_one_to_one():
    from vmctl_core.guestos.registry import default_registry

    assert default_registry.for_os("mac-os-x-tiger").abs_pointer_gain == 1.178
    assert default_registry.for_os("mac-os-9").abs_pointer_gain == 1.0
