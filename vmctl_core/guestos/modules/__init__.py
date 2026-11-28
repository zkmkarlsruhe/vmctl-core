"""Concrete GuestOS modules.

One module per OS family. The capability sets are wired (consumed by the
controller's ``instance_view`` / capabilities endpoint and the web log viewer); the
imperative behaviour bodies are still being extracted from the controller (the
phased plan in research/32). The Windows-XP module names the exact existing
controller code each method will absorb. Mac OS 9 declares almost nothing — it is
the proof the capability model degrades cleanly.
"""

from vmctl_core.guestos.modules.linux import LinuxModule
from vmctl_core.guestos.modules.mac_os_7 import MacOS7Module
from vmctl_core.guestos.modules.mac_os_9 import MacOS9Module
from vmctl_core.guestos.modules.mac_os_x import MacOSXModule, MacOSXTigerModule
from vmctl_core.guestos.modules.windows_7 import Windows7Module
from vmctl_core.guestos.modules.windows_2003 import Windows2003Module
from vmctl_core.guestos.modules.windows_modern import WindowsModernModule
from vmctl_core.guestos.modules.windows_xp import WindowsXPModule

__all__ = [
    "LinuxModule",
    "MacOS7Module",
    "MacOS9Module",
    "MacOSXModule",
    "MacOSXTigerModule",
    "Windows7Module",
    "Windows2003Module",
    "WindowsModernModule",
    "WindowsXPModule",
]
