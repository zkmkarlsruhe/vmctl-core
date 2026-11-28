"""Windows Server 2003 / XP x64 (NT 5.2).

Same era as XP (NT 5.1): the CryptoAPI is SHA-1 by default on 2003 RTM and only gains
SHA-2 after patching (like XP SP3), so a MITM leg must present a legacy (SHA-1 / TLSv1)
cert profile. This module subclasses the XP module to INHERIT that correct legacy profile,
the TCP-first agent transport, and the capability set — only the OS labels and display name
differ.

Without it, a ``windows-2003`` label falls to the modern-Windows fallback and would be handed
a SHA-256 / TLS1.2 profile — which a pre-patch 2003 guest cannot validate through the MITM.
"""

from __future__ import annotations

from vmctl_core.guestos.modules.windows_xp import WindowsXPModule


class Windows2003Module(WindowsXPModule):
    os_labels: tuple[str, ...] = (
        "windows-2003",
        "win2003",
        "windows-server-2003",
        "server-2003",
        "windows-xp-x64",
    )
    display_name = "Windows Server 2003"
