"""VM backend abstraction + implementations.

`base.VMBackend` is the contract every backend implements; the controller talks
only to this Protocol so the same code runs against different substrates:

* ``LibvirtBackend`` — libvirt (qemu:///system), incl. the qemu-system-ppc mac9 tier.
* ``SheepShaverBackend`` / ``BasiliskIIBackend`` — classic-Mac SDL2 emulators over
  an Xvfb+x11vnc process group, NOT libvirt (research/52).

``registry.backend_for(base, name, ...)`` selects the right one from the catalog's
``hw.backend`` field (research/52 §3), replacing the hardcoded ``LibvirtBackend``.
"""

from .base import BackendError, VMBackend
from .libvirt_backend import LibvirtBackend
from .mac_emu import (
    BasiliskIIBackend,
    MacEmuSettings,
    SheepShaverBackend,
    render_prefs,
)
from .registry import backend_for, is_mac_emu, resolve_backend_kind

__all__ = [
    "BackendError",
    "BasiliskIIBackend",
    "LibvirtBackend",
    "MacEmuSettings",
    "SheepShaverBackend",
    "VMBackend",
    "backend_for",
    "is_mac_emu",
    "render_prefs",
    "resolve_backend_kind",
]
