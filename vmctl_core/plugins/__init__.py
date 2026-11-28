"""The shared plugin spec + runtime.

A plugin is the deliverable that moves research -> exhibition. Both controllers
import this runtime so a plugin runs unchanged in either. The registration
surface is kept compatible with exhibition's original plugins.py.
"""

from vmctl_core.plugins.contract import plugin_spec
from vmctl_core.plugins.runtime import (
    LoadedPlugin,
    PluginRegistry,
    PluginRequest,
    PluginResponse,
    load_plugins,
)
from vmctl_core.plugins.scaffold import new_plugin, slugify
from vmctl_core.plugins.spec import MANIFEST_FILENAME, PluginManifest, PluginTarget

__all__ = [
    "MANIFEST_FILENAME",
    "LoadedPlugin",
    "PluginManifest",
    "PluginRegistry",
    "PluginRequest",
    "PluginResponse",
    "PluginTarget",
    "load_plugins",
    "new_plugin",
    "plugin_spec",
    "slugify",
]
