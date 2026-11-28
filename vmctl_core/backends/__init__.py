"""VM backend abstraction + implementations.

`base.VMBackend` is the contract every backend implements; the controller talks
only to this Protocol so the same code runs against different substrates:

* ``LibvirtBackend`` — libvirt (qemu:///system), incl. the qemu-system-ppc mac9 tier.
* ``SheepShaverBackend`` / ``BasiliskIIBackend`` — classic-Mac SDL2 emulators over
  an Xvfb+x11vnc process group, NOT libvirt (research/52).
* ``Q800Backend`` — qemu-system-m68k -M q800 as a process with QMP + VNC (research/70c).
* ``ProcessBackend`` — any emulator run from one command line, e.g. MAME or FS-UAE.

``registry.backend_for(base, name, ...)`` selects the right one from the catalog's
``hw.backend`` field (research/52 §3), replacing the hardcoded ``LibvirtBackend``.
"""

from vmctl_core.backends.base import BackendError, VMBackend
from vmctl_core.backends.libvirt_backend import LibvirtBackend
from vmctl_core.backends.mac_emu import (
    BasiliskIIBackend,
    MacEmuSettings,
    SheepShaverBackend,
    render_prefs,
)
from vmctl_core.backends.process import ProbeSpec, ProcessBackend, ProcessSpec, clone_process
from vmctl_core.backends.qemu_q800 import AgentUnreachable, Q800Backend, clone_q800, q800_spec
from vmctl_core.backends.registry import (
    backend_for,
    is_mac_emu,
    is_process_backend,
    resolve_backend_kind,
)

__all__ = [
    "AgentUnreachable",
    "BackendError",
    "BasiliskIIBackend",
    "LibvirtBackend",
    "MacEmuSettings",
    "ProbeSpec",
    "ProcessBackend",
    "ProcessSpec",
    "Q800Backend",
    "SheepShaverBackend",
    "VMBackend",
    "backend_for",
    "clone_process",
    "clone_q800",
    "is_mac_emu",
    "is_process_backend",
    "q800_spec",
    "render_prefs",
    "resolve_backend_kind",
]
