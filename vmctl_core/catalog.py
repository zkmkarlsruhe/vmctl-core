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


class AuxDisk(BaseModel):
    """An extra boot disk attached AHEAD of the main clone — e.g. the OpenCore
    bootloader qcow2 for a macOS golden. Like the main golden it is a read-only
    BASE that clone.py gives a per-clone writable overlay (qemu has no readonly
    IDE/SATA disks, and a shared writable disk would corrupt); OpenCore writes its
    NVRAM to that overlay. Boots first, then chainloads macOS off the main disk."""

    path: str  # abs path to the shared read-only base image (e.g. the OpenCore qcow2)
    bus: str = "sata"  # ich9-AHCI (what q35 ide.N maps to; the proven Snow Leopard bus)
    boot: int = 1  # libvirt <boot order>; lower boots earlier (OpenCore = 1)


class Hardware(BaseModel):
    """Per-base hardware shape. Defaults suit a modern Linux guest."""

    machine: str = "pc"  # generic i440fx alias (host-version-agnostic)
    arch: str = "x86_64"
    # Which VMBackend runs this base (research/52). '' => inferred: 'libvirt' for
    # everything, incl. the qemu-system-ppc mac9 (9.2.2) tier; 'basilisk2' for
    # m68k. Set 'sheepshaver' (PPC, 8.1-9.0.4 NewWorld-ROM) or 'basilisk2' (68k,
    # System 7-8.1) to run a classic-Mac base under the SDL2/Xvfb/x11vnc emulator
    # backend instead of libvirt. 'q800' = qemu-system-m68k -M q800 as a process with
    # QMP + VNC (libvirt refuses m68k domains, research/70c §7.1). These two need a Mac ROM (a host prereq — see
    # 'rom' below + VMCTL_* env; NOT baked into a base — research/18).
    backend: str = ""
    process: dict = Field(default_factory=dict)  # ProcessSpec template, including pinned media
    rom: str = ""  # per-base Mac ROM path override for sheepshaver/basilisk2.
    # '' => the deployment ROM from config (VMCTL_NEWWORLD_ROM / VMCTL_ROM_68K).
    # q800: the golden PRAM image (qcow2, relative to the catalog like `path`). Carries
    # 32-bit addressing + startup settings (research/70b §3.4); cloned per instance.
    nvram: str = ""
    # Pin the host ROM a base needs (q800: checksum F1ACAD13). The ROM itself stays a
    # host prerequisite (VMCTL_ROM_68K / `rom`), never inside a base or bundle.
    rom_checksum: str = ""  # first 4 bytes of the ROM, hex, e.g. 'F1ACAD13'
    rom_sha256: str = ""
    # q800: the emulator container image the golden was built + verified on. The id
    # (sha256 config digest, `docker image inspect -f {{.Id}}`) is what runs; the reference
    # (e.g. harbor.zkm.de/mutech/vmctl-emu/qemu-m68k:11.1.1-zkm1) says where to pull it.
    # '' => the host's qemu-system-m68k (VMCTL_QEMU_M68K_BIN).
    emulator_image: str = ""
    emulator_image_id: str = ""
    mac_screen: str = ""  # sheepshaver/basilisk SDL2 screen, e.g. 'win/1024/768'
    # (q800: the `-g` mode, e.g. '640x480x8'; '' => 640x480x8)
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
    # Guest sound for rvmc's browser audio: a libvirt <sound> model whose driver ships in the
    # guest (ac97, ich6, ich9, sb16, es1370), 'onboard' (ppc screamer, q800 ASC), or '' = none.
    # rvmc enables host capture into the per-VM null sink for every new instance when set.
    sound: str = ""
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
    memballoon: str = "virtio"  # 'none' for guests without the balloon driver (pristine XP)

    # --- macOS-x86 (Hackintosh-style, e.g. Snow Leopard 10.6) knobs. Inert unless
    # hw.macos is set; the template only reads them in the macos branch. macOS needs
    # OVMF firmware, a Penryn CPU spoofing GenuineIntel, the Apple SMC device (no
    # native libvirt element -> qemu:commandline), and an OpenCore boot disk. Pair with
    # disk_bus='sata', nic_model='e1000', video='vmvga', virtio_serial=False,
    # agent_channel=False, memballoon='none' (no virtio/vioser drivers on macOS -> the
    # guest agent runs legacy-TCP on :9009 over the NAT NIC, research/64 tiger tier).
    macos: bool = False  # select the macOS libvirt/qemu shape (OVMF + applesmc + OpenCore)
    loader: str = ""  # OVMF firmware path emitted as <loader type='rom'> / -bios
    smc: bool = False  # emit -device isa-applesmc,osk=... via <qemu:commandline>
    osk: str = ""  # the 64-char Apple SMC key (the public Snow Leopard key works for 10.6)
    cpu_features: list[str] = Field(default_factory=list)  # e.g. ['sse4.1','sse4.2','ssse3']
    cpu_vendor: str = ""  # <cpu><vendor> — 'Intel' spoofs GenuineIntel (needed on AMD/EPYC hosts)
    aux_disks: list[AuxDisk] = Field(default_factory=list)  # extra boot disks (OpenCore)

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


def _os_key(name: str) -> str:
    return (name or "").strip().lower().replace(" ", "-")


class BaseImage(BaseModel):
    """One catalog entry — an immutable golden qcow2 + how to boot it."""

    id: str
    name: str | None = None  # human-friendly display name (UI falls back to id)
    path: str  # qcow2 path (abs, or relative to the catalog file)
    os: str  # free-form label, e.g. "windows-xp", "linux"
    # Broader OS classes this base also runs (artwork-autopsy's base picks, e.g. "windows-9x",
    # "osx-legacy"): the analysis pre-fills a base whose os OR os_aliases names its pick.
    os_aliases: list[str] = Field(default_factory=list)
    agent: bool = False  # qemu-guest-agent available in this guest?
    notes: str | None = None
    hw: Hardware = Field(default_factory=Hardware)

    def runs(self, os_name: str) -> bool:
        """Whether this base runs ``os_name`` (its os or an alias; case and spaces ignored)."""
        want = _os_key(os_name)
        return bool(want) and any(_os_key(o) == want for o in (self.os, *self.os_aliases))

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
