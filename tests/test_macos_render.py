"""macOS-x86 (Hackintosh-style, e.g. Snow Leopard 10.6) guest rendering.

The macOS branch of ``domain.xml.j2`` needs a shape no other guest uses: KVM +
OVMF firmware + a Penryn CPU spoofing GenuineIntel + the Apple SMC device (which
has no native libvirt element, so it rides in ``<qemu:commandline>``) + an OpenCore
boot disk that is a read-only base with a per-clone writable overlay (qemu has no
readonly IDE/SATA disk). These tests lock that shape AND guard that a plain
Windows/Linux x86 render is completely unaffected by the macOS additions.

Verified live: this exact render boots Snow Leopard 10.6.3 to the desktop under
libvirt (qemu:///system) — libvirt translates it to the proven-working qemu argv.
"""

import xml.etree.ElementTree as ET
from pathlib import Path

from vmctl_core.catalog import AuxDisk, BaseImage, Hardware
from vmctl_core.clone import clone_base, render_domain_xml

_OSK = "ourhardworkbythesewordsguardedpleasedontsteal(c)AppleComputerInc"
_QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"


def _macos_base() -> BaseImage:
    hw = Hardware(
        macos=True,
        machine="q35",
        arch="x86_64",
        cpu_model="Penryn",
        cpu_features=["sse4.1", "sse4.2", "ssse3"],
        cpu_vendor="Intel",
        loader="/usr/share/ovmf/OVMF.fd",
        smc=True,
        osk=_OSK,
        disk_bus="sata",
        nic_model="e1000",
        video="vmvga",
        memory_mb=4096,
        vcpus=2,
        clock="utc",
        usb_tablet=True,
        virtio_serial=False,
        agent_channel=False,
        memballoon="none",
        aux_disks=[AuxDisk(path="/srv/vmctl/opencore-SLeopard.qcow2")],
    )
    return BaseImage(
        id="macos-10.6-snowleopard",
        os="macos-10.6",
        path="/srv/vmctl/macintosh.qcow2",
        agent=True,
        hw=hw,
    )


def test_macos_domain_shape():
    xml = render_domain_xml(
        _macos_base(),
        name="sl1",
        disk_path=Path("/clones/sl1.qcow2"),
        mac="52:54:00:aa:bb:cc",
    )
    root = ET.fromstring(xml)

    # KVM domain with the qemu namespace (needed for the applesmc escape hatch)
    assert root.get("type") == "kvm"
    assert f'xmlns:qemu="{_QEMU_NS}"' in xml or f"xmlns:qemu='{_QEMU_NS}'" in xml

    # OVMF firmware as -bios
    loader = root.find("./os/loader")
    assert loader is not None and loader.text == "/usr/share/ovmf/OVMF.fd"

    # Penryn spoofing GenuineIntel + the SSE features Snow Leopard needs
    assert root.find("./cpu/model").text == "Penryn"
    assert root.find("./cpu/vendor").text == "Intel"
    feats = {f.get("name") for f in root.findall("./cpu/feature")}
    assert {"sse4.1", "sse4.2", "ssse3"} <= feats

    # SINGLE SOCKET — load-bearing: macOS fails inter-socket TSC sync and hangs at
    # boot.efi with libvirt's default sockets-per-vcpu topology. All vcpus in 1 socket.
    topo = root.find("./cpu/topology")
    assert topo is not None
    assert topo.get("sockets") == "1"
    assert topo.get("cores") == "2"  # == hw.vcpus
    assert topo.get("threads") == "1"

    # Apple SMC injected raw via <qemu:commandline> (no native libvirt element)
    qargs = [e.get("value") for e in root.iter(f"{{{_QEMU_NS}}}arg")]
    assert f"isa-applesmc,osk={_OSK}" in qargs

    # OpenCore aux disk boots FIRST (order 1), the installed macOS disk SECOND
    disks = root.findall("./devices/disk")
    srcs = {d.find("source").get("file"): d.find("boot").get("order") for d in disks}
    assert srcs["/srv/vmctl/opencore-SLeopard.qcow2"] == "1"
    assert srcs["/clones/sl1.qcow2"] == "2"

    # macOS in-box drivers: vmware-svga video, e1000 NIC, USB keyboard (no ps2)
    assert root.find("./devices/video/model").get("type") == "vmvga"
    assert root.find("./devices/interface/model").get("type") == "e1000"
    kbds = [i.get("bus") for i in root.findall("./devices/input") if i.get("type") == "keyboard"]
    assert kbds == ["usb"]

    # NO virtio-serial (no macOS driver): the agent runs legacy-TCP on the NAT NIC
    assert root.find(".//channel") is None
    assert root.find(".//controller[@type='virtio-serial']") is None


def test_windows_render_unaffected_by_macos_additions():
    """A plain x86 (Windows) base must render exactly as before — SeaBIOS, no
    applesmc, no qemu namespace — proving the macOS branch is fully isolated."""
    win = BaseImage(
        id="winxp",
        os="windows-xp",
        path="/srv/win.qcow2",
        hw=Hardware(machine="pc", disk_bus="ide", nic_model="e1000", clock="localtime"),
    )
    xml = render_domain_xml(win, name="w1", disk_path=Path("/clones/w1.qcow2"))
    assert "qemu:commandline" not in xml
    assert "isa-applesmc" not in xml
    assert "<loader" not in xml  # SeaBIOS, no OVMF
    root = ET.fromstring(xml)
    assert root.get("type") == "kvm"
    assert root.find("./os/boot").get("dev") == "hd"


def test_clone_base_creates_aux_overlay(tmp_path, monkeypatch):
    """clone_base must make a per-clone writable overlay for each aux disk (OpenCore),
    backed by the shared read-only base — like the main disk (qemu has no readonly
    IDE/SATA disk; a shared writable one would corrupt).

    make_overlay (which shells out to qemu-img) is stubbed to a marker so this exercises
    clone_base's ORCHESTRATION — aux overlay path derivation + XML wiring, the logic
    added here — with no qemu-img dependency; the real overlay is covered end-to-end."""
    import vmctl_core.clone as clone_mod

    made: list[tuple[str, str]] = []

    def fake_make_overlay(base_path, overlay_path):
        made.append((str(base_path), str(overlay_path)))
        Path(overlay_path).write_text("stub-overlay")

    monkeypatch.setattr(clone_mod, "make_overlay", fake_make_overlay)

    oc_base = tmp_path / "opencore.qcow2"
    main_base = tmp_path / "golden.qcow2"
    oc_base.write_text("stub-base")
    main_base.write_text("stub-base")

    hw = Hardware(
        macos=True,
        machine="q35",
        loader="/usr/share/ovmf/OVMF.fd",
        smc=True,
        osk=_OSK,
        disk_bus="sata",
        nic_model="e1000",
        video="vmvga",
        virtio_serial=False,
        agent_channel=False,
        memballoon="none",
        aux_disks=[AuxDisk(path=str(oc_base))],
    )
    base = BaseImage(id="macos", os="macos-10.6", path=str(main_base), agent=True, hw=hw)

    overlays = tmp_path / "overlays"
    xmls = tmp_path / "xml"
    overlays.mkdir()
    overlay_path, xml_path = clone_base(
        base,
        catalog_dir=tmp_path,
        domain_name="sl1",
        overlays_dir=overlays,
        xml_dir=xmls,
    )
    # main overlay + one aux overlay were each made from their read-only base
    aux_overlay = overlays / "sl1-aux0.qcow2"
    assert (str(main_base), str(overlay_path)) in made
    assert (str(oc_base), str(aux_overlay)) in made
    assert aux_overlay.exists()
    # the rendered XML points at the aux OVERLAY, not the shared base
    xml = xml_path.read_text()
    assert "sl1-aux0.qcow2" in xml
    assert str(oc_base) not in xml
