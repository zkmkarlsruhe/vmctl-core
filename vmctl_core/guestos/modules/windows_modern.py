"""Modern Windows reference module (Windows 8.x / 10 / 11).

Same Windows agent surface as Win7 (event log via wevtutil, CA via certutil,
policies.json browser trust, in-box drivers) but a modern cert profile (SHA-256,
TLS 1.2 floor). NOTE the catalog-level twist that drives this whole feature: the
Win10 *golden* ships ``agent:false`` — so although this module DECLARES the agent
capabilities, the registry/controller strip the agent-dependent ones via
``gate_by_agent`` when the resolved base image has no agent. An agentless Win10
therefore exposes only host log sources + the hypervisor-level controls.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, CertProfile


class WindowsModernModule(BaseGuestOSModule):
    os_labels: tuple[str, ...] = (
        "windows-modern",
        "windows-8",
        "win8",
        "windows-8.1",
        "windows-10",
        "win10",
        "windows-11",
        "win11",
    )
    display_name = "Windows (modern)"

    def caps(self) -> Capabilities:
        return Capabilities.of(
            Capability.READ_EVENT_LOG,  # wevtutil
            Capability.INSTALL_CA,  # certutil
            Capability.INSTALL_CA_BROWSER,  # policies.json
            Capability.CERT_PROFILE,
            Capability.PROVISION_DRIVERS,  # mostly in-box virtio
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
            name="modern",
            leaf_hash="sha256",
            cipher_profile="modern",
            tls_min="TLSv1_2",
            detail="windows-modern: SHA-256, TLS1.2 floor",
        )

    def agent_transport(self, ctx) -> str:
        return "vioser"
