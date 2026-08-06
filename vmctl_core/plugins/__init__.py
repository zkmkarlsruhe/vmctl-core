"""The shared plugin spec + runtime.

A plugin is the deliverable that moves research -> exhibition. Both controllers
import this runtime so a plugin runs unchanged in either. The registration
surface is kept compatible with exhibition's original plugins.py.
"""

from .contract import plugin_spec
from .runtime import (
    LoadedPlugin,
    PluginRegistry,
    PluginRequest,
    PluginResponse,
    load_plugins,
)
from .scaffold import new_plugin, slugify
from .spec import MANIFEST_FILENAME, PluginManifest, PluginTarget

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
