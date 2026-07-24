"""Capability negotiation for guest-OS modules.

A module declares the subset of the contract it actually supports. The controller
checks ``module.caps()`` before calling a behaviour method; the UI/AI hide or grey
out unsupported actions instead of raising. This is what lets Mac OS 9 (no event
log, no Firefox NSS trust DB, no in-guest agent) coexist with Windows XP behind one
contract without every caller sprouting ``if os == ...`` branches.
"""

from __future__ import annotations

from enum import StrEnum


class Capability(StrEnum):
    """One togglable behaviour a GuestOS module may or may not support."""

    READ_LOGS = "read_logs"  # generic text logs (journald/syslog/Console)
    READ_EVENT_LOG = "read_event_log"  # Windows structured EventLog specifically
    INSTALL_CA = "install_ca"  # add a root CA to the system trust store
    INSTALL_CA_BROWSER = "install_ca_browser"  # also into the browser's own store (Firefox NSS)
    CERT_PROFILE = "cert_profile"  # has a SHA-1/SHA-256/TLS-floor opinion (MITM)
    PROVISION_DRIVERS = "provision_drivers"  # install paravirtual drivers (virtio/QXL)
    AGENT = "agent"  # an in-guest agent can run here at all
    CONFIGURE_PROXY = "configure_proxy"
    CONFIGURE_BROWSER = "configure_browser"  # proxy/HSTS/TLS hardening of the browser
    HANDLE_DIALOGS = "handle_dialogs"  # auto-click security/installer dialogs
    AUDIO_SETUP = "audio_setup"  # in-guest audio routing/unmute
    DATALINK_MOUNT = "datalink_mount"  # mount the host->guest share inside the guest
    SET_RESOLUTION = "set_resolution"  # change the display mode from inside the guest
    MAKE_GOLDEN = "make_golden"  # has a documented golden-image recipe


class Capabilities(frozenset):
    """An immutable set of :class:`Capability`. ``cap in caps`` is the check."""

    @classmethod
    def of(cls, *caps: Capability) -> Capabilities:
        return cls(caps)

    def supports(self, cap: Capability) -> bool:
        return cap in self

    def as_list(self) -> list[str]:
        """Stable, JSON-serialisable list of capability values (for the API/UI)."""
        return sorted(c.value for c in self)


#: Capabilities that depend on an in-guest agent being present. When a base image
#: declares no agent (``BaseImage.agent == False``, e.g. the Win10 golden) these are
#: stripped from the module's declared set — research/32: "the agent row gates many
#: others". ``read_event_log`` and ``set_resolution`` and the scriptable
#: proxy/CA/browser/dialog actions all run *through* the agentbox.
AGENT_DEPENDENT: frozenset[Capability] = frozenset(
    {
        Capability.AGENT,
        Capability.READ_EVENT_LOG,
        Capability.READ_LOGS,
        Capability.INSTALL_CA,
        Capability.INSTALL_CA_BROWSER,
        Capability.CONFIGURE_PROXY,
        Capability.CONFIGURE_BROWSER,
        Capability.HANDLE_DIALOGS,
        Capability.SET_RESOLUTION,
    }
)


def gate_by_agent(caps: Capabilities, agent: bool) -> Capabilities:
    """Drop the agent-dependent capabilities when the guest has no agent.

    Mac OS 9 modules already declare none of these, so this is a no-op there; the
    real driver is the Win10 golden which is *Windows* (so the module declares the
    full set) but ships ``agent:false`` — its agent-only controls must be hidden."""
    if agent:
        return caps
    return Capabilities(caps - AGENT_DEPENDENT)
