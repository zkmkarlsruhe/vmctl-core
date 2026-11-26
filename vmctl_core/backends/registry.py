"""Backend selection — resolve which VMBackend a base image needs (research/52 §3).

Pays off the research/32 §F debt (``DEFAULT_EMULATOR`` was hardcoded x86): instead
of the controller constructing ``LibvirtBackend`` directly, it asks
``backend_for(base, name, ...)``. The kind comes from the NEW catalog field
``hw.backend`` (``libvirt`` | ``sheepshaver`` | ``basilisk2``), defaulting to a
safe inference so EVERY existing base — including the qemu-system-ppc mac9 (9.2.2)
domain, which stays on libvirt — keeps its current backend unchanged.
"""

from __future__ import annotations

from ..catalog import BaseImage
from .base import VMBackend
from .libvirt_backend import LibvirtBackend
from .mac_emu import BasiliskIIBackend, MacEmuSettings, SheepShaverBackend
from .process import ProcessBackend
from .qemu_q800 import Q800Backend

# valid explicit hw.backend values
LIBVIRT = "libvirt"
SHEEPSHAVER = "sheepshaver"
BASILISK2 = "basilisk2"
Q800 = "q800"  # qemu-system-m68k -M q800 as a process (QMP + VNC), research/70c
PROCESS = "process"  # any emulator run from one command line, defined by process.json
_MAC_KINDS = (SHEEPSHAVER, BASILISK2)
_PROCESS_KINDS = (*_MAC_KINDS, Q800, PROCESS)


def resolve_backend_kind(base: BaseImage) -> str:
    """The backend kind for a base. Explicit ``hw.backend`` wins; otherwise inferred
    conservatively so nothing existing changes:

    * ``m68k``/``68k`` arch -> ``q800`` when ``machine: q800``, else ``basilisk2``
    * everything else (incl. arch ``ppc`` = the libvirt mac9 tier) -> ``libvirt``

    Note: arch ``ppc`` does NOT infer sheepshaver — the shipped mac9 golden runs
    9.2.2 under qemu-system-ppc (above SheepShaver's MMU ceiling), so SheepShaver is
    opt-in via an explicit ``backend: sheepshaver`` only.
    """
    kind = (getattr(base.hw, "backend", "") or "").strip().lower()
    if kind:
        if kind not in (LIBVIRT, *_PROCESS_KINDS):
            raise ValueError(
                f"base {base.id!r}: unknown hw.backend {kind!r} "
                f"(expected one of {LIBVIRT!r}, {SHEEPSHAVER!r}, {BASILISK2!r}, {Q800!r}, {PROCESS!r})"
            )
        return kind
    if (base.hw.arch or "").strip().lower() in ("m68k", "68k"):
        return Q800 if (base.hw.machine or "").strip().lower() == "q800" else BASILISK2
    return LIBVIRT


def is_mac_emu(base: BaseImage) -> bool:
    """True for a SheepShaver/Basilisk base (the Xvfb/x11vnc process backend)."""
    return resolve_backend_kind(base) in _MAC_KINDS


def is_process_backend(base: BaseImage) -> bool:
    """True for every non-libvirt base (SheepShaver, Basilisk II, q800)."""
    return resolve_backend_kind(base) in _PROCESS_KINDS


def backend_for(
    base: BaseImage,
    name: str,
    *,
    libvirt_uri: str = "qemu:///system",
    mac_settings: MacEmuSettings | None = None,
    disk: str | None = None,
    instance_dir: str | None = None,
    extfs_dir: str | None = None,
    cdrom: str | None = None,
    display_num: int = 80,
    vnc_port: int = 5980,
    audio_sink: str = "",
) -> VMBackend:
    """Construct the right backend for ``base`` bound to instance ``name``.

    For ``libvirt`` only ``libvirt_uri`` matters (identical to today's
    ``LibvirtBackend(name, uri=...)``). For the classic-Mac kinds the caller passes
    the per-instance runtime it already computes elsewhere: the cloned ``.dsk``
    (``disk``), the ``extfs`` shared dir (wire to the drive's ``work/datalink/files``
    per research/68), display + VNC port (so x11vnc lands where the tokens.d/
    websockify map expects), and the audio null sink.
    """
    kind = resolve_backend_kind(base)
    if kind == LIBVIRT:
        return LibvirtBackend(name, uri=libvirt_uri)
    if kind == Q800:
        # q800 keeps its whole definition in instance_dir (written by clone_q800 + define)
        if not str(instance_dir or "").strip():
            raise ValueError(f"q800 backend for {name!r} requires instance_dir")
        return Q800Backend(
            name, instance_dir=str(instance_dir), settings=mac_settings or MacEmuSettings()
        )

    if kind == PROCESS:
        if not str(instance_dir or "").strip():
            raise ValueError(f"process backend for {name!r} requires instance_dir")
        return ProcessBackend(name, instance_dir=str(instance_dir))

    if not str(disk or "").strip():
        raise ValueError(f"{kind} backend for {name!r} requires an instance disk (.dsk)")
    settings = mac_settings or MacEmuSettings()
    common = dict(
        settings=settings,
        disk=disk,
        instance_dir=instance_dir,
        extfs_dir=extfs_dir,
        cdrom=cdrom,
        screen=(base.hw.mac_screen or "win/1024/768"),
        memory_mb=base.hw.memory_mb,
        display_num=display_num,
        vnc_port=vnc_port,
        audio_sink=audio_sink or base.hw.audio_sink,
    )
    rom_override = getattr(base.hw, "rom", "") or None
    cls = SheepShaverBackend if kind == SHEEPSHAVER else BasiliskIIBackend
    return cls(name, rom=rom_override, **common)
