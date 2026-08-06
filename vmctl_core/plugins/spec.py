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


class PluginClaim(BaseModel):
    """A network flow a backend-shim plugin claims — the router's admission hint (rung-0).

    ``backend_host`` is the shorthand for the common case (one HTTP(S) host); ``claims`` is the
    explicit form that also constrains ports / protocols / methods / paths, so a plugin can (e.g.)
    take POST on ``/api/*`` without swallowing the whole host. The router matches a live ``Flow``
    against these; the plugin still SERVES via ``serve_request`` — the claim is only who-gets-it.

    Defaults are the safe HTTP(S) shape so a bare ``host`` behaves like today's ``backend_host``.
    Note (codex): plugins claim application traffic (http / router-terminated https) here; raw
    TCP/UDP and DNS are SEPARATE explicit capabilities, not folded into this claim.
    """

    host: str  # fnmatch pattern, as backend_host is today
    ports: list[int] = Field(default_factory=lambda: [80, 443])
    protocols: list[str] = Field(default_factory=lambda: ["http", "https"])
    methods: list[str] = Field(default_factory=list)  # empty = any method
    paths: list[str] = Field(default_factory=list)  # empty = any path (fnmatch)


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
    # A backend-shim plugin (capability ``backend-shim``) impersonates a network host the recovered
    # client calls — e.g. the baked backend host of a legacy artwork. The host controller routes that
    # host to this plugin as the FIRST entry in the project's guest-proxy chain (plugin first, then
    # the wayback/archive backends). Empty => not a network shim (a UI/tool plugin).
    backend_host: str | None = None
    # Explicit, additive claim list (see PluginClaim). Empty + backend_host set => one default
    # HTTP(S) claim on that host (back-compat). Use effective_claims() to get the resolved set.
    claims: list[PluginClaim] = Field(default_factory=list)

    def effective_claims(self) -> list[PluginClaim]:
        """The resolved claim set: explicit ``claims`` if given, else the ``backend_host``
        shorthand expanded to a single default HTTP(S) claim, else empty (not a network shim)."""
        if self.claims:
            return list(self.claims)
        if self.backend_host:
            return [PluginClaim(host=self.backend_host)]
        return []


MANIFEST_FILENAME = "manifest.yaml"
