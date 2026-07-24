"""Windows 7 reference module.

Windows 7 keeps the full Windows agent surface (event log, scriptable CA/proxy/
browser, virtio-win drivers, AutoIt dialogs) but resolves a modern-ish cert
profile (SHA-256 is fine; TLS 1.2 with the platform update). Distinct from XP only
in `cert_profile`; the behaviour bodies are otherwise the Windows family's.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, CertProfile


class Windows7Module(BaseGuestOSModule):
    os_labels: tuple[str, ...] = ("windows-7", "win7")
    display_name = "Windows 7"

    def caps(self) -> Capabilities:
        return Capabilities.of(
            Capability.READ_EVENT_LOG,  # wevtutil / advapi32
            Capability.INSTALL_CA,
            Capability.INSTALL_CA_BROWSER,
            Capability.CERT_PROFILE,
            Capability.PROVISION_DRIVERS,  # virtio-win
            Capability.AGENT,
            Capability.CONFIGURE_PROXY,
            Capability.CONFIGURE_BROWSER,
            Capability.HANDLE_DIALOGS,
            Capability.AUDIO_SETUP,
            Capability.DATALINK_MOUNT,
            Capability.SET_RESOLUTION,
            Capability.MAKE_GOLDEN,
        )

    def cert_profile(self, ctx, *, probe=True) -> CertProfile:
        return CertProfile(
            name="legacy_sha2",
            leaf_hash="sha256",
            cipher_profile="legacy",
            tls_min="TLSv1",
            detail="windows-7: SHA-256 ok, TLS1.0 floor",
        )

    def agent_transport(self, ctx) -> str:
        return "vioser"
