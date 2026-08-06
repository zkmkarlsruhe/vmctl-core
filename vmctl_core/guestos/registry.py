"""GuestOS module registry — resolve a module from a catalog OS label.

Mirrors the resolution the controller already does with ``_base_os(inst)`` ->
inline branches, but as a lookup: ``registry.for_os(base.os)``. Matching is
longest-prefix over each module's ``os_labels`` so "windows-xp" beats a generic
"windows" fallback, and an unknown label falls back to a safe generic module
(today: a Windows-ish or no-op module, decided at wiring time).
"""

from __future__ import annotations

from .contract import GuestOSModule


class GuestOSRegistry:
    def __init__(self) -> None:
        self._modules: list[GuestOSModule] = []
        self._fallback: GuestOSModule | None = None

    def register(self, module: GuestOSModule) -> None:
        self._modules.append(module)

    def set_fallback(self, module: GuestOSModule) -> None:
        self._fallback = module

    def for_os(self, os_label: str | None) -> GuestOSModule:
        label = (os_label or "").lower()
        best: GuestOSModule | None = None
        best_len = -1
        for m in self._modules:
            for lbl in m.os_labels:
                lbl = lbl.lower()
                if (label == lbl or label.startswith(lbl) or lbl in label) and len(lbl) > best_len:
                    best, best_len = m, len(lbl)
        if best is not None:
            return best
        if self._fallback is not None:
            return self._fallback
        raise KeyError(f"no GuestOS module for os label {os_label!r}")

    def all(self) -> list[GuestOSModule]:
        return list(self._modules)


# Process-wide default registry, populated with the shipped OS modules. The
# fallback is the modern-Windows module (the most common unknown-label guest); an
# agentless / classic guest is still gated correctly because the controller strips
# agent-dependent caps from whatever module resolves (see gate_by_agent).
default_registry = GuestOSRegistry()


def _populate_default_registry() -> None:
    # imported here (not at module top) so registry.py has no import cycle with the
    # modules, which import contract/capabilities.
    from .modules import (
        LinuxModule,
        MacOS9Module,
        MacOSXModule,
        Windows7Module,
        Windows2003Module,
        WindowsModernModule,
        WindowsXPModule,
    )

    for cls in (
        WindowsXPModule,
        Windows2003Module,
        Windows7Module,
        WindowsModernModule,
        LinuxModule,
        MacOS9Module,
        MacOSXModule,
    ):
        default_registry.register(cls())
    default_registry.set_fallback(WindowsModernModule())


_populate_default_registry()
