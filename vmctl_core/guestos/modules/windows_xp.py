"""Windows XP reference module (NON-WIRED STUB).

This is the spine of Phase 2: the deepest XP coupling, behind the contract. Each
method's docstring names the exact existing rvmc/controller.py (or wbc.py) code it
will absorb verbatim — no behaviour change — so the extraction is a mechanical move.
Nothing here is called by the live controller yet.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, CertProfile, EventRecord


class WindowsXPModule(BaseGuestOSModule):
    os_labels: tuple[str, ...] = (
        "windows-xp",
        "winxp",
        "windows-2000",
        "win2000",
        "windows-nt",
        "windows-9x",
    )
    display_name = "Windows XP"

    def caps(self) -> Capabilities:
        return Capabilities.of(
            Capability.READ_EVENT_LOG,  # controller._GUEST_EVTLOG_PY / guest_event_log
            Capability.INSTALL_CA,  # controller._WIN_CA_INSTALL_PY (crypt32 LOCAL_MACHINE\ROOT)
            Capability.INSTALL_CA_BROWSER,  # controller._WIN_FF_AUTOCONFIG_PY (FF52 ESR NSS / enterprise roots)
            Capability.CERT_PROFILE,  # controller._WBC_OS_PROFILE + _wbc_runtime_refine_profile
            Capability.PROVISION_DRIVERS,  # virtio-win CD insert + AutoIt wizard walk
            Capability.AGENT,  # the agentbox (Python 3.4 + AutoIt)
            Capability.CONFIGURE_PROXY,  # controller.wbc_apply_guest_proxy (WinINET reg + netsh)
            Capability.CONFIGURE_BROWSER,  # controller._WIN_FF_HARDEN_PY
            Capability.HANDLE_DIALOGS,  # rvmc-input.au3 (AutoIt) via the agent
            Capability.AUDIO_SETUP,  # ac97/ich6 in-box drivers; mostly host-side
            Capability.DATALINK_MOUNT,  # universal CD (datalink.py) — no driver needed
            Capability.SET_RESOLUTION,  # rvmc_agent t_set_resolution / controller._RES_PY (ChangeDisplaySettingsW)
            Capability.MAKE_GOLDEN,
        )

    def cert_profile(self, ctx, *, probe=True) -> CertProfile:
        """ABSORBS: controller._wbc_static_cert_profile + _wbc_runtime_refine_profile.
        Static = legacy_nosha2 (SHA-1; XP pre-SP3 has no SHA-2 in CryptoAPI); probe
        bumps build 2600 + 'Service Pack 3' -> legacy_sha2 (SHA-256)."""
        return CertProfile(
            name="legacy_nosha2",
            leaf_hash="sha1",
            cipher_profile="legacy",
            tls_min="TLSv1",
            detail="stub: static legacy_nosha2 (no probe)",
        )

    def agent_transport(self, ctx) -> str:
        """ABSORBS: controller._agent_endpoint policy — vioser socket if the channel
        exists, else TCP (guest_ip, 9009) over rtl8139 (pristine XP, no virtio)."""
        return "tcp"  # pristine XP default; vioser after drivers

    def read_event_log(self, ctx, *, log="System", count=50) -> list[EventRecord]:
        """ABSORBS: controller.guest_event_log + _GUEST_EVTLOG_PY (advapi32
        OpenEventLogW/ReadEventLogW ctypes fallback; XP has no wevtutil)."""
        return []  # stub

    def make_golden_steps(self) -> list[str]:
        return [
            "fresh XP install on IDE disk, vga video, rtl8139 NIC, localtime+hyperv",
            "boot driver-wizard-free (agent_channel=False, memballoon=none)",
            "bootstrap agentbox over TCP:9009; install Python 3.4 + AutoIt + rvmc_agent",
            "insert virtio-win CD; provision vioser/virtio/QXL via the AutoIt wizard",
            "autostart agentbox dual-transport via HKLM Run; snapshot 'ready'",
        ]
