"""Self-describing plugin contract.

`plugin_spec()` returns, in one structure, everything an author (human OR an AI
agent in the chat loop) needs to write a plugin that loads in EITHER controller:

  - the manifest schema (the PluginManifest JSON schema),
  - the registry contract: every ``register_*`` method on PluginRegistry with its
    signature + a one-line description,
  - the plugin directory layout + the setup(registry) entrypoint convention.

It is derived from the live code (the manifest pydantic schema + introspection of
PluginRegistry), so it can never drift from what the loader actually accepts — that
is what makes authoring a plugin a first-class, machine-readable capability.
"""

from __future__ import annotations

import inspect

from .runtime import PluginRegistry
from .spec import MANIFEST_FILENAME, PluginManifest

# Hand-written one-liners for each registration method (what to register + when it
# fires). Keys must match PluginRegistry.register_* method names; verified by a test
# that every register_* method is covered.
_REGISTER_DOCS: dict[str, str] = {
    "register_web_handler": (
        "handler(path: str) -> str | bytes | None. Serve the plugin's web UI; "
        "return HTML/bytes for a path or None to pass through. Reached at "
        "/plugins/<pid>/<path> (research) and the plugin's web mount (exhibition)."
    ),
    "register_state_provider": (
        "name, provider() -> dict. Expose a named blob of live state (read by the "
        "controller / AI / UI via plugin_state). Keep it cheap + JSON-serialisable."
    ),
    "register_poll_provider": (
        "resource, handler() -> str. Answer a short string for a polled resource "
        "(e.g. an Arduino/exhibition poll). Falls back to the last set_poll_value."
    ),
    "register_signal_handler": (
        "event, handler(value: str) -> None. React to a fired signal "
        "(/api/v1/signal/<event>); also pushed to SSE listeners."
    ),
    "register_startup_hook": (
        "hook() -> None. Run once when the controller has loaded the plugin."
    ),
    "register_shutdown_hook": ("hook() -> None. Run on controller shutdown / plugin unload."),
    "register_pre_restart_hook": (
        "hook() -> True | str. Veto a guest restart by returning a reason string; "
        "return True to allow."
    ),
    "register_post_restart_hook": ("hook() -> None. Run after a guest restart completes."),
}


def _registry_contract() -> list[dict]:
    out: list[dict] = []
    for name in sorted(n for n in dir(PluginRegistry) if n.startswith("register_")):
        method = getattr(PluginRegistry, name)
        try:
            sig = str(inspect.signature(method)).replace("(self, ", "(").replace("(self)", "()")
        except (TypeError, ValueError):
            sig = "(...)"
        out.append(
            {
                "method": name,
                "signature": f"registry.{name}{sig}",
                "doc": _REGISTER_DOCS.get(name, ""),
            }
        )
    return out


def plugin_spec() -> dict:
    """The full, self-describing plugin contract (see module docstring)."""
    return {
        "layout": {
            "directory": "a plugin is a directory under the project's plugin workspace",
            "files": {
                MANIFEST_FILENAME: "the PluginManifest (see manifest_schema)",
                "plugin.py": "module exposing `def setup(registry): ...` (the entrypoint)",
                "web/": "optional static assets the plugin serves via its web handler",
            },
            "entrypoint": (
                "plugin.py must define `def setup(registry): ...`; it is called once "
                "with a PluginRegistry. Register capabilities there. The SAME file runs "
                "unchanged in the exhibition controller."
            ),
        },
        "manifest_schema": PluginManifest.model_json_schema(),
        "manifest_example": PluginManifest(
            id="my-plugin", name="My Plugin", description="what it does for the artwork"
        ).model_dump(),
        "registry": _registry_contract(),
        "notes": [
            "setup(registry) runs in the controller process — keep imports light and "
            "side-effect-free at import time; do work inside the registered callables.",
            "state/poll providers should be fast and must not raise; the controller "
            "catches and reports errors but a slow provider blocks the state read.",
            "after writing files, call plugin_bind() to (re)load the plugin into the "
            "controller and see load errors/tracebacks.",
        ],
    }
