"""Linux / Debian reference module.

The existing controller already has Linux branches (`_LINUX_FF_ENTERPRISE_SH`,
`_install_ca_linux`, gsettings proxy, xrandr). This module declares their
capabilities. The key difference from Windows for the log viewer: Linux has NO
Windows event log — its guest logs are text (journald / syslog), surfaced via
``read_logs`` (Capability.READ_LOGS), never ``win:*``.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, CertProfile, LogRecord


class LinuxModule(BaseGuestOSModule):
    os_labels: tuple[str, ...] = ("linux", "debian", "ubuntu", "fedora", "arch")
    display_name = "Linux"

    def caps(self) -> Capabilities:
        return Capabilities.of(
            Capability.AGENT,  # the agent runs here (qemu-guest-agent / rvmc_agent)
            Capability.READ_LOGS,  # journald / syslog (NOT win:*)
            Capability.INSTALL_CA,  # update-ca-certificates
            Capability.INSTALL_CA_BROWSER,  # Firefox policies.json / NSS
            Capability.CERT_PROFILE,  # n/a system trust, but has an opinion
            Capability.PROVISION_DRIVERS,  # virtio mostly in-box
            Capability.CONFIGURE_PROXY,  # gsettings + /etc/profile.d
            Capability.CONFIGURE_BROWSER,
            Capability.HANDLE_DIALOGS,  # xdotool best-effort
            Capability.AUDIO_SETUP,
            Capability.DATALINK_MOUNT,  # virtiofs/9p or CD
            Capability.SET_RESOLUTION,  # xrandr
            Capability.MAKE_GOLDEN,
        )

    def cert_profile(self, ctx, *, probe=True) -> CertProfile:
        return CertProfile(
            name="modern",
            leaf_hash="sha256",
            cipher_profile="modern",
            tls_min="TLSv1_2",
            detail="linux: system trust, modern TLS",
        )

    def agent_transport(self, ctx) -> str:
        return "vioser"

    def read_logs(self, ctx, *, kind="system", count=50) -> list[LogRecord]:
        """ABSORBS (phase 3): journalctl / syslog tail via the agent. Stub for now."""
        return []
