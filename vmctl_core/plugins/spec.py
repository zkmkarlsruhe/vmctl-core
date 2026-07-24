"""The shared plugin spec — the contract a plugin conforms to.

A plugin is the unit that moves research -> exhibition. It is a directory:

    my-plugin/
      manifest.yaml      # this schema
      plugin.py          # exposes `def setup(registry): ...`
      web/               # optional static assets the plugin serves

Both controllers load plugins through this spec, so a plugin built and tested in
the research workbench runs unchanged in the exhibition runtime.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class PluginTarget(BaseModel):
    """What artwork/guest this plugin is for (informational + filtering)."""

    os: str | None = None  # e.g. "windows-xp", "linux"
    base_id: str | None = None  # a specific catalog base, if tied to one


class PluginManifest(BaseModel):
    id: str
    name: str
    version: str = "0.1.0"
    author: str | None = None
    license: str = "MIT"
    entrypoint: str = "plugin.py"  # module (relative to the plugin dir) with setup()
    target: PluginTarget = Field(default_factory=PluginTarget)
    capabilities: list[str] = Field(default_factory=list)
    description: str | None = None


MANIFEST_FILENAME = "manifest.yaml"
