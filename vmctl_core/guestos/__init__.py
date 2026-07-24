"""Pluggable per-guest-OS modules (a.k.a. platform adapters).

PROPOSAL / NON-WIRED SKELETON. This package makes the GuestOS contract concrete so
it can be reviewed; **no controller caller is rewired to it yet** (see
research-vm-controller/research/32-guest-os-modules.md, the phased plan).

A ``GuestOSModule`` encapsulates everything the controller currently does inline as
"if windows: crypt32 ... else: update-ca-certificates ...". One module per OS family,
bound to a base image via the catalog: ``BaseImage.os`` -> ``registry.for_os(os)``.

The contract is split into two halves:

* **declarative** — ``GuestOSModule.caps()`` returns a ``Capabilities`` set, so the
  UI/AI can degrade gracefully when an OS lacks a feature (e.g. no event log on
  Mac OS 9). A capability the module does not declare must not be called.
* **imperative** — the behaviour methods (``install_ca``, ``read_event_log``,
  ``configure_proxy`` ...). Each takes a ``GuestContext`` (the live handle the
  controller already has: the guest-call shim + the resolved base) so a module is a
  pure strategy object with no controller state of its own.

This composes with — does NOT replace — the existing ``VMBackend`` (hypervisor
abstraction) and the plugin spec/registry. ``VMBackend`` is "how do I talk to this
hypervisor"; ``GuestOSModule`` is "given a running guest, how does THIS OS do X".
"""

from __future__ import annotations

from .capabilities import AGENT_DEPENDENT, Capabilities, Capability, gate_by_agent
from .context import GuestContext
from .contract import CertProfile, EventRecord, GuestOSModule, LogRecord
from .registry import GuestOSRegistry, default_registry

__all__ = [
    "AGENT_DEPENDENT",
    "Capabilities",
    "Capability",
    "CertProfile",
    "EventRecord",
    "GuestContext",
    "GuestOSModule",
    "GuestOSRegistry",
    "LogRecord",
    "default_registry",
    "gate_by_agent",
]
