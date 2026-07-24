"""The GuestOS module contract — the methods each per-OS adapter implements.

This is the centrepiece. Every method that the controller currently runs inline
with an ``if windows: ... else: ...`` branch (CA install, event log, proxy, browser
hardening, cert profile, driver provisioning, dialogs, audio, datalink, golden
recipe) moves behind this Protocol. The controller resolves the right module from
the catalog OS label and dispatches:

    module = registry.for_os(base.os)
    if module.caps().supports(Capability.READ_EVENT_LOG):
        return module.read_event_log(ctx, log="System", count=50)

A module is stateless: every method takes a :class:`GuestContext`. Unsupported
methods are NOT stubbed to raise everywhere — the default base class raises
``Unsupported`` and the matching capability is simply absent from ``caps()``, so
well-behaved callers never reach them.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .capabilities import Capabilities
from .context import GuestContext


class Unsupported(NotImplementedError):
    """Raised when a capability the module does not declare is called anyway."""


# --- value types the contract speaks in (OS-neutral) ----------------------------
@dataclass
class LogRecord:
    """One line of a generic text log (journald / syslog / macOS unified log)."""

    ts: str = ""
    level: str = ""
    source: str = ""
    message: str = ""


@dataclass
class EventRecord(LogRecord):
    """A structured Windows EventLog record (superset of LogRecord)."""

    event_id: int = 0
    record_number: int = 0
    category: str = ""


@dataclass
class CertProfile:
    """The MITM cert knobs an OS version needs the proxy to honour.

    Mirrors wbc.CERT_PROFILES today (leaf_hash, cipher_profile, tls_min) plus the
    resolved profile name and how it was decided, so the runtime SP-probe refinement
    (XP RTM->SP3 = SHA-1->SHA-256) becomes a per-module concern.
    """

    name: str = "legacy_nosha2"  # legacy_nosha2 | legacy_sha2 | modern
    leaf_hash: str = "sha1"  # sha1 | sha256
    cipher_profile: str = "legacy"  # legacy | modern
    tls_min: str = "TLSv1"  # TLSv1 | TLSv1_2
    detail: str = ""  # how it was resolved (e.g. "xp-sp3 -> legacy_sha2")


# --- the contract ---------------------------------------------------------------
@runtime_checkable
class GuestOSModule(Protocol):
    """A platform adapter for one guest-OS family."""

    #: catalog os labels this module claims (matched case-insensitively, prefix-ish)
    os_labels: tuple[str, ...]
    #: human name for UI ("Windows XP", "Mac OS 9", ...)
    display_name: str

    def caps(self) -> Capabilities:
        """The subset of the contract this module supports. Drives UI/AI degradation."""

    # --- logs ---------------------------------------------------------------
    def read_logs(
        self, ctx: GuestContext, *, kind: str = "system", count: int = 50
    ) -> list[LogRecord]:
        """Generic text logs: journald (Linux), unified log/Console (macOS), text logs."""

    def read_event_log(
        self, ctx: GuestContext, *, log: str = "System", count: int = 50
    ) -> list[EventRecord]:
        """Windows structured EventLog (System/Application/Security)."""

    # --- trust / certs ------------------------------------------------------
    def cert_profile(self, ctx: GuestContext, *, probe: bool = True) -> CertProfile:
        """Resolve the MITM cert profile for this guest (static map + optional runtime probe)."""

    def install_ca(
        self, ctx: GuestContext, *, cert_pem: bytes, profile: CertProfile, browser: bool = True
    ) -> dict:
        """Install a root CA into the system (and optionally browser) trust store."""

    # --- drivers / provisioning --------------------------------------------
    def provision_drivers(self, ctx: GuestContext, *, driver_iso: str | None = None) -> dict:
        """Install paravirtual drivers (virtio/QXL/vioser). No-op where in-box."""

    def make_golden_steps(self) -> list[str]:
        """Human/AI-readable ordered recipe to turn a fresh install into a golden base."""

    # --- agent transport ----------------------------------------------------
    def agent_transport(self, ctx: GuestContext) -> str:
        """Preferred agent transport for this OS: 'vioser' | 'tcp' | 'none'."""

    # --- browser / proxy ----------------------------------------------------
    def configure_proxy(self, ctx: GuestContext, *, addr: str, bypass: str = "") -> dict:
        """Point the system/browser at the proxy (WinINET+netsh / gsettings+profile.d / ...)."""

    def clear_proxy(self, ctx: GuestContext) -> dict: ...

    def configure_browser(
        self,
        ctx: GuestContext,
        *,
        proxy_addr: str = "",
        disable_hsts: bool = True,
        relax_tls: bool = True,
    ) -> dict:
        """Harden the browser for archived content (proxy + HSTS + TLS floor)."""

    # --- input / dialogs ----------------------------------------------------
    def handle_dialogs(self, ctx: GuestContext, *, kind: str = "security_warning") -> dict:
        """Auto-dismiss/confirm a known OS/security dialog (AutoIt on Windows, ...)."""

    # --- hardware-ish -------------------------------------------------------
    def audio_setup(self, ctx: GuestContext) -> dict:
        """In-guest audio routing/unmute (host sink wiring is the backend's job)."""

    def datalink_mount(self, ctx: GuestContext) -> dict:
        """Surface the host->guest share inside the guest. Default OS path = the
        universal CD (no agent), modern Linux may prefer virtiofs/9p."""

    def set_resolution(self, ctx: GuestContext, *, width: int, height: int) -> dict: ...


# --- a base class that turns 'capability absent' into a clean error -------------
class BaseGuestOSModule:
    """Convenience base: every contract method raises Unsupported by default, so a
    concrete module only overrides what it declares in ``caps()``. Subclasses set
    ``os_labels`` / ``display_name`` and implement their supported methods."""

    os_labels: tuple[str, ...] = ()
    display_name: str = "unknown"

    def caps(self) -> Capabilities:
        return Capabilities()

    def _unsupported(self, name: str):
        raise Unsupported(f"{self.display_name} does not support {name!r}")

    def read_logs(self, ctx, *, kind="system", count=50):
        self._unsupported("read_logs")

    def read_event_log(self, ctx, *, log="System", count=50):
        self._unsupported("read_event_log")

    def cert_profile(self, ctx, *, probe=True):
        self._unsupported("cert_profile")

    def install_ca(self, ctx, *, cert_pem, profile, browser=True):
        self._unsupported("install_ca")

    def provision_drivers(self, ctx, *, driver_iso=None):
        self._unsupported("provision_drivers")

    def make_golden_steps(self):
        return []

    def agent_transport(self, ctx):
        return "none"

    def configure_proxy(self, ctx, *, addr, bypass=""):
        self._unsupported("configure_proxy")

    def clear_proxy(self, ctx):
        self._unsupported("clear_proxy")

    def configure_browser(self, ctx, *, proxy_addr="", disable_hsts=True, relax_tls=True):
        self._unsupported("configure_browser")

    def handle_dialogs(self, ctx, *, kind="security_warning"):
        self._unsupported("handle_dialogs")

    def audio_setup(self, ctx):
        self._unsupported("audio_setup")

    def datalink_mount(self, ctx):
        self._unsupported("datalink_mount")

    def set_resolution(self, ctx, *, width, height):
        self._unsupported("set_resolution")
