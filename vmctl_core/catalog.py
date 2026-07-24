"""Base-image catalog.

A catalog is a small YAML file listing the immutable golden images a deployment
offers, each with the hardware hints needed to boot that guest correctly (legacy
Windows wants IDE + localtime + hyperv; Linux wants virtio + UTC). Clones are
copy-on-write overlays on top of these read-only bases.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field

# disk bus -> first disk target dev name
_DISK_DEV = {"ide": "hda", "sata": "sda", "scsi": "sda", "virtio": "vda"}


class Hardware(BaseModel):
    """Per-base hardware shape. Defaults suit a modern Linux guest."""

    machine: str = "pc"  # generic i440fx alias (host-version-agnostic)
    arch: str = "x86_64"
    # Which VMBackend runs this base (research/52). '' => inferred: 'libvirt' for
    # everything, incl. the qemu-system-ppc mac9 (9.2.2) tier; 'basilisk2' for
    # m68k. Set 'sheepshaver' (PPC, 8.1-9.0.4 NewWorld-ROM) or 'basilisk2' (68k,
    # System 7-8.1) to run a classic-Mac base under the SDL2/Xvfb/x11vnc emulator
    # backend instead of libvirt. These two need a Mac ROM (a host prereq — see
    # 'rom' below + VMCTL_* env; NOT baked into a base — research/18).
    backend: str = ""
    rom: str = ""  # per-base Mac ROM path override for sheepshaver/basilisk2.
    # '' => the deployment ROM from config (VMCTL_NEWWORLD_ROM / VMCTL_ROM_68K).
    mac_screen: str = ""  # sheepshaver/basilisk SDL2 screen, e.g. 'win/1024/768'
    # (windowed => the 1:1 hardware-cursor mouse path, research/52 §5).
    # '' => 'win/1024/768'. NOT 'dga'.
    # Per-base QEMU binary. None => deployment x86 default (DEFAULT_EMULATOR /
    # RvmcConfig.emulator). Set to e.g. /opt/qemu-screamer/bin/qemu-system-ppc for
    # the PowerPC/mac99 (Mac OS 9, screamer-audio fork) bases — research/33b, /38.
    emulator: str | None = None
    cpu_model: str = ""  # explicit <cpu> model (ppc: 'g4'/'g3'); '' => host-passthrough
    # ppc/mac99 (Mac OS 9) knobs. Inert on x86 — the template only reads them in
    # the arch=='ppc' branch.
    via: str = "pmu"  # mac99 VIA mode: pmu => working USB mouse/kbd
    boot_dev: str = "hd"  # 'cdrom' to boot the install CD first (then flip to hd)
    boot_iso: str | None = None  # abs path to a boot/install ISO baked into the CD drive
    blank_disk_gb: int = 0  # >0 => clone makes a fresh empty qcow2 of this size instead of a
    # CoW overlay (no golden base yet — e.g. an OS-install project VM)
    audio_sink: str = ""  # screamer -audiodev pa out.name (per-VM null sink); '' => no audio arg
    prom_env: list[str] = (
        Field(  # OpenBIOS prom-env vars via <qemu:commandline> (no native libvirt field)
            default_factory=lambda: ["auto-boot?=true", "boot-args=-v", "vga-ndrv?=true"]
        )
    )
    disk_bus: str = "virtio"  # ide for WinXP/9x, sata/virtio for modern
    nic_model: str = "virtio"  # e1000 / rtl8139 for pristine legacy guests
    video: str = "qxl"  # qxl|vga|cirrus|virtio. Legacy Windows = vga (in-box
    # VBE driver: no install + surface tracks the guest mode,
    # so the usb-tablet maps 1:1 at every resolution — research/23)
    vgamem_mb: int = 16  # std/vga/cirrus framebuffer; 64 for legacy multi-res menus
    qxl_ram_mb: int = 64  # qxl only
    qxl_vram_mb: int = 64  # qxl only
    memory_mb: int = 2048
    vcpus: int = 2
    clock: str = "utc"  # localtime for Windows
    hyperv: bool = False  # True for Windows guests
    usb_tablet: bool = True  # absolute pointer — smoother in noVNC
    vmport: bool = False  # VMware backdoor — NT4 absolute pointer (vmvga+VMware mouse drv)
    agent_channel: bool = True  # emit the virtio-serial agentbox channel (needs vioser in guest;
    # False for pristine XP so it boots driver-wizard-free)
    virtio_serial: bool = True  # virtio-serial controller + qemu-ga channel (needs vioser driver)
    mgmt_nic: bool = False  # emit an ADDITIONAL isolated host-only NIC on the 'rvmc-mgmt'
    # network (private 10.77.0.0/24, no forward). Containment for the legacy-TCP agent
    # transport: guests with no virtio-serial (win2000/win98/irix) run the agentbox on
    # TCP:9009; this puts that lane on an isolated NIC the untrusted artwork LAN can't
    # reach, and guest_ip() then prefers the 10.77.0.x lease so the controller/tcp_helper
    # dial the mgmt IP, not the artwork NIC. Off by default => single-NIC domains unchanged.
    memballoon: str = "virtio"  # 'none' for guests without the balloon driver (pristine XP)

    @property
    def disk_dev(self) -> str:
        return _DISK_DEV.get(self.disk_bus, "vda")

    # libvirt wants these in KiB
    @property
    def vgamem_kib(self) -> int:
        return self.vgamem_mb * 1024

    @property
    def qxl_ram_kib(self) -> int:
        return self.qxl_ram_mb * 1024

    @property
    def qxl_vram_kib(self) -> int:
        return self.qxl_vram_mb * 1024


class BaseImage(BaseModel):
    """One catalog entry — an immutable golden qcow2 + how to boot it."""

    id: str
    name: str | None = None  # human-friendly display name (UI falls back to id)
    path: str  # qcow2 path (abs, or relative to the catalog file)
    os: str  # free-form label, e.g. "windows-xp", "linux"
    agent: bool = False  # qemu-guest-agent available in this guest?
    notes: str | None = None
    hw: Hardware = Field(default_factory=Hardware)

    def resolved_path(self, catalog_dir: Path) -> Path:
        p = Path(self.path)
        return p if p.is_absolute() else (catalog_dir / p).resolve()


class Catalog(BaseModel):
    bases: list[BaseImage] = Field(default_factory=list)

    def get(self, base_id: str) -> BaseImage:
        for b in self.bases:
            if b.id == base_id:
                return b
        raise KeyError(f"base image {base_id!r} not in catalog")


def load_catalog(path: str | Path) -> Catalog:
    """Load a catalog.yaml. Paths inside resolve relative to its directory."""
    path = Path(path)
    data = yaml.safe_load(path.read_text()) or {}
    return Catalog(**data)
