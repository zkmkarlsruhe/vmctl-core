"""Plugin runtime — registry + loader.

The PluginRegistry surface is kept byte-compatible with exhibition's original
plugins.py (web/signal/poll/state/lifecycle hooks + SSE), so a plugin written
against this runtime runs in either controller. The loader is the one addition:
it discovers manifest-described plugin DIRECTORIES (the shared spec) rather than
flat .py files.
"""

from __future__ import annotations

import asyncio
import importlib.util
import json
import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

from .spec import MANIFEST_FILENAME, PluginManifest

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Central registry for plugin capabilities (exhibition-compatible surface)."""

    def __init__(self) -> None:
        self._poll_providers: dict[str, Callable[[], str]] = {}
        self._signal_handlers: dict[str, Callable[[str], None]] = {}
        self._state_providers: dict[str, Callable[[], dict]] = {}
        self._startup_hooks: list[Callable] = []
        self._shutdown_hooks: list[Callable] = []
        self._pre_restart_hooks: list[Callable] = []
        self._post_restart_hooks: list[Callable] = []
        self._sse_clients: list[asyncio.Queue] = []
        # A per-project registry can load SEVERAL plugin dirs (load_plugins iterates a
        # directory), each of which may register a web handler. Keep them ALL and try
        # each in turn — a single slot would let the last-loaded plugin's UI silently
        # shadow every earlier one. The contract already says a handler returns None to
        # "pass through", so chaining is the documented semantics.
        self._web_handlers: list[Callable] = []
        self._poll_state: dict[str, str] = {}
        self.loaded: list[LoadedPlugin] = []
        # Read-only host services the controller may attach BEFORE load_plugins() so a
        # plugin's setup(registry) can capture them (a signal handler only gets `value`,
        # so this is how a plugin reaches shared state). `tools` = the ToolsLibrary
        # catalog, so a plugin derives tool availability/gaps from the single source of
        # truth instead of hard-coding a staged-list. None when the host didn't attach it.
        self.tools = None

    # --- registration -----------------------------------------------------
    def register_poll_provider(self, resource: str, handler: Callable[[], str]) -> None:
        self._poll_providers[resource] = handler

    def register_signal_handler(self, event: str, handler: Callable[[str], None]) -> None:
        self._signal_handlers[event] = handler

    def register_state_provider(self, name: str, provider: Callable[[], dict]) -> None:
        self._state_providers[name] = provider

    def register_web_handler(self, handler: Callable) -> None:
        self._web_handlers.append(handler)

    def register_startup_hook(self, hook: Callable) -> None:
        self._startup_hooks.append(hook)

    def register_shutdown_hook(self, hook: Callable) -> None:
        self._shutdown_hooks.append(hook)

    def register_pre_restart_hook(self, hook: Callable[[], bool]) -> None:
        self._pre_restart_hooks.append(hook)

    def register_post_restart_hook(self, hook: Callable) -> None:
        self._post_restart_hooks.append(hook)

    # --- dispatch ---------------------------------------------------------
    def get_poll_value(self, resource: str) -> str:
        if resource in self._poll_providers:
            try:
                return self._poll_providers[resource]()
            except Exception as e:
                logger.error("poll provider %r failed: %s", resource, e, exc_info=True)
        return self._poll_state.get(resource, "none")

    def set_poll_value(self, resource: str, value: str) -> None:
        self._poll_state[resource] = value

    def handle_signal(self, event: str, value: str) -> bool:
        handler = self._signal_handlers.get(event)
        if not handler:
            logger.info("signal %r (no handler)", event)
            return False
        try:
            handler(value)
        except Exception as e:
            logger.error("signal handler %r failed: %s", event, e, exc_info=True)
            return False
        if self._sse_clients:
            self.push_event("signal", json.dumps({"event": event, "value": value}))
        return True

    def get_state(self) -> dict:
        state: dict = {}
        for name, provider in self._state_providers.items():
            try:
                state[name] = provider()
            except Exception as e:
                state[name] = {"error": str(e)}
        return state

    def check_pre_restart(self) -> str | None:
        for hook in self._pre_restart_hooks:
            try:
                result = hook()
                if result is not True:
                    return result if isinstance(result, str) else "Restart blocked by plugin"
            except Exception as e:
                logger.error("pre-restart hook failed: %s", e, exc_info=True)
        return None

    def run_post_restart(self) -> None:
        for hook in self._post_restart_hooks:
            try:
                hook()
            except Exception as e:
                logger.error("post-restart hook failed: %s", e, exc_info=True)

    def serve_web(self, path: str):
        for handler in self._web_handlers:
            try:
                result = handler(path)
            except Exception as e:
                logger.error("web handler for %r failed: %s", path, e)
                continue
            if result is not None:
                return result
        return None

    def get_startup_hooks(self) -> list[Callable]:
        return self._startup_hooks

    def get_shutdown_hooks(self) -> list[Callable]:
        return self._shutdown_hooks

    # --- SSE --------------------------------------------------------------
    def sse_connect(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._sse_clients.append(q)
        return q

    def sse_disconnect(self, q: asyncio.Queue) -> None:
        if q in self._sse_clients:
            self._sse_clients.remove(q)

    def push_event(self, event: str, data: str) -> None:
        for q in self._sse_clients:
            q.put_nowait((event, data))


@dataclass
class LoadedPlugin:
    manifest: PluginManifest
    path: Path


def load_plugins(
    plugins_dir: str | Path,
    registry: PluginRegistry,
    *,
    only: list[str] | None = None,
) -> list[LoadedPlugin]:
    """Discover manifest-described plugin directories under ``plugins_dir`` and
    call each plugin's ``setup(registry)``. Returns the loaded plugins."""
    plugins_dir = Path(plugins_dir)
    if not plugins_dir.is_dir():
        return []

    loaded: list[LoadedPlugin] = []
    for child in sorted(plugins_dir.iterdir()):
        manifest_file = child / MANIFEST_FILENAME
        if not (child.is_dir() and manifest_file.is_file()):
            continue
        try:
            manifest = PluginManifest(**(yaml.safe_load(manifest_file.read_text()) or {}))
        except Exception as e:
            logger.error("bad manifest in %s: %s", child, e)
            continue
        if only is not None and manifest.id not in only:
            continue

        entry = child / manifest.entrypoint
        if not entry.is_file():
            logger.error("plugin %r entrypoint missing: %s", manifest.id, entry)
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"rvmc_plugin_{manifest.id}", entry)
            module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            if not hasattr(module, "setup"):
                logger.error("plugin %r has no setup(registry)", manifest.id)
                continue
            module.setup(registry)
            lp = LoadedPlugin(manifest=manifest, path=child)
            registry.loaded.append(lp)
            loaded.append(lp)
            logger.info("loaded plugin %r v%s", manifest.id, manifest.version)
        except Exception as e:
            logger.error("error loading plugin %r: %s", manifest.id, e, exc_info=True)
    return loaded
