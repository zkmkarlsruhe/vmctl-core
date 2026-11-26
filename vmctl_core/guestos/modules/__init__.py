"""Concrete GuestOS modules.

One module per OS family. The capability sets are wired (consumed by the
controller's ``instance_view`` / capabilities endpoint and the web log viewer); the
imperative behaviour bodies are still being extracted from the controller (the
phased plan in research/32). The Windows-XP module names the exact existing
controller code each method will absorb. Mac OS 9 declares almost nothing — it is
the proof the capability model degrades cleanly.
"""

from .linux import LinuxModule
from .mac_os_7 import MacOS7Module
from .mac_os_9 import MacOS9Module
from .mac_os_x import MacOSXModule, MacOSXTigerModule
from .windows_7 import Windows7Module
from .windows_2003 import Windows2003Module
from .windows_modern import WindowsModernModule
from .windows_xp import WindowsXPModule

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
