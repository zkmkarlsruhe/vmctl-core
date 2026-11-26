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
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from .spec import MANIFEST_FILENAME, PluginManifest

if TYPE_CHECKING:  # type-only: the runtime never needs the catalog module imported
    from ..tools import ToolsLibrary

logger = logging.getLogger(__name__)

#: Per-client SSE backlog cap. An exhibition browser tab that stops reading (a sleeping kiosk,
#: a wedged frontend) would otherwise grow its queue without bound over a run of weeks. When a
#: queue is full the OLDEST event is dropped: the newest state is what a display needs, and the
#: memory stays bounded whether anyone reads or not.
SSE_QUEUE_MAXSIZE = 1000


@dataclass(frozen=True)
class PluginRequest:
    """A backend-style request handed to a plugin request handler (framework-neutral).

    Unlike ``serve_web`` (path-only, GET, UI-serving), this carries the WHOLE request so a plugin can
    serve a query-param DATA API — e.g. an artwork's ``xml.php?m=<mode>&q=<query>`` contract. ``path``
    is the plugin-relative path (after ``/plugins/<pid>/``); ``query`` is the parsed query string.
    """

    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    body: bytes = b""


@dataclass(frozen=True)
class PluginResponse:
    """A content-typed response from a plugin request handler."""

    body: str | bytes
    content_type: str = "text/html; charset=utf-8"
    status: int = 200


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
        # SSE clients: (queue, owning-loop). push_event runs from ANY thread (handle_signal is
        # dispatched on the FastAPI sync threadpool), while sse_connect/sse_disconnect run on the
        # event loop. A lock guards the list so push_event iterates a stable SNAPSHOT — otherwise a
        # concurrent sse_disconnect().remove() shifts the list mid-iteration and one client is
        # silently skipped. The loop is captured at connect time so a non-loop-thread push can
        # marshal put_nowait back onto the queue's loop via call_soon_threadsafe (see push_event).
        self._sse_lock = threading.Lock()
        self._sse_clients: list[tuple[asyncio.Queue, asyncio.AbstractEventLoop | None]] = []
        # A per-project registry can load SEVERAL plugin dirs (load_plugins iterates a
        # directory), each of which may register a web handler. Keep them ALL and try
        # each in turn — a single slot would let the last-loaded plugin's UI silently
        # shadow every earlier one. The contract already says a handler returns None to
        # "pass through", so chaining is the documented semantics.
        self._web_handlers: list[Callable] = []
        # Backend request handlers (query-param data APIs). Same chain-until-first-non-None
        # semantics as _web_handlers; see register_request_handler / serve_request.
        self._request_handlers: list[Callable] = []
        self._poll_state: dict[str, str] = {}
        self.loaded: list[LoadedPlugin] = []
        # Owner tracking for transactional / hot-reload loads. During load_plugins each
        # register_* records the (collection, item) it added under the plugin currently
        # being loaded (_current_owner), so a RELOAD can replace that plugin's prior
        # registrations instead of accumulating stale web/request/startup/shutdown hooks,
        # and a FAILED load can be rolled back to the pre-load state.
        self._current_owner: str | None = None
        self._owned: dict[str, list[tuple[str, object | None, object]]] = {}
        # Read-only host services the controller may attach BEFORE load_plugins() so a
        # plugin's setup(registry) can capture them (a signal handler only gets `value`,
        # so this is how a plugin reaches shared state). `tools` = the ToolsLibrary
        # catalog, so a plugin derives tool availability/gaps from the single source of
        # truth instead of hard-coding a staged-list. None when the host didn't attach it.
        self.tools: ToolsLibrary | None = None

    # --- registration -----------------------------------------------------
    #: mutable registration collections a load snapshots / rolls back (dicts key by
    #: resource/event/name; lists hold the callables).
    _REGISTRATION_COLLECTIONS = (
        "_poll_providers",
        "_signal_handlers",
        "_state_providers",
        "_startup_hooks",
        "_shutdown_hooks",
        "_pre_restart_hooks",
        "_post_restart_hooks",
        "_web_handlers",
        "_request_handlers",
    )

    def _record(self, collection: str, value: object, *, key: object | None = None) -> None:
        """Attribute a registration to the plugin currently being loaded (if any), so a
        reload can replace it and a failed load can be rolled back. No-op for direct,
        non-load registrations (``_current_owner`` is None). For a dict-backed collection
        pass ``key`` so _clear_owner removes it ONLY while it still maps to THIS plugin's
        value — never clobbering another plugin's later override of the same key."""
        if self._current_owner is not None:
            self._owned.setdefault(self._current_owner, []).append((collection, key, value))

    def register_poll_provider(self, resource: str, handler: Callable[[], str]) -> None:
        self._poll_providers[resource] = handler
        self._record("_poll_providers", handler, key=resource)

    def register_signal_handler(self, event: str, handler: Callable[[str], None]) -> None:
        self._signal_handlers[event] = handler
        self._record("_signal_handlers", handler, key=event)

    def register_state_provider(self, name: str, provider: Callable[[], dict]) -> None:
        self._state_providers[name] = provider
        self._record("_state_providers", provider, key=name)

    def register_web_handler(self, handler: Callable) -> None:
        self._web_handlers.append(handler)
        self._record("_web_handlers", handler)

    def register_request_handler(self, handler: Callable) -> None:
        self._request_handlers.append(handler)
        self._record("_request_handlers", handler)

    def register_startup_hook(self, hook: Callable) -> None:
        self._startup_hooks.append(hook)
        self._record("_startup_hooks", hook)

    def register_shutdown_hook(self, hook: Callable) -> None:
        self._shutdown_hooks.append(hook)
        self._record("_shutdown_hooks", hook)

    def register_pre_restart_hook(self, hook: Callable[[], bool]) -> None:
        self._pre_restart_hooks.append(hook)
        self._record("_pre_restart_hooks", hook)

    def register_post_restart_hook(self, hook: Callable) -> None:
        self._post_restart_hooks.append(hook)
        self._record("_post_restart_hooks", hook)

    # --- load transaction (snapshot / rollback / per-plugin replace) ------
    def _snapshot_registrations(self) -> dict:
        snap: dict = {}
        for a in self._REGISTRATION_COLLECTIONS:
            v = getattr(self, a)
            snap[a] = dict(v) if isinstance(v, dict) else list(v)
        snap["_owned"] = {k: list(v) for k, v in self._owned.items()}
        return snap

    def _restore_registrations(self, snap: dict) -> None:
        for a in self._REGISTRATION_COLLECTIONS:
            cur = getattr(self, a)
            v = snap[a]
            if isinstance(cur, dict):
                cur.clear()
                cur.update(v)
            else:
                cur[:] = v
        self._owned.clear()
        self._owned.update({k: list(v) for k, v in snap["_owned"].items()})

    def _clear_owner(self, pid: str) -> None:
        """Remove every registration a PRIOR load of ``pid`` added (reload = replace,
        not accumulate). Dict entries are removed only while the key still maps to THIS
        plugin's value (so we never drop another plugin's later override of the same key);
        list entries remove the exact registered object."""
        for collection, key, value in self._owned.pop(pid, []):
            coll = getattr(self, collection)
            if key is not None:  # dict-backed
                if coll.get(key) is value:
                    del coll[key]
            else:  # list-backed: remove by IDENTITY (list.remove uses __eq__, which a
                # hook with a custom __eq__ could exploit to drop another plugin's object)
                for i, existing in enumerate(coll):
                    if existing is value:
                        del coll[i]
                        break

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
        # A handler DECLINES a path by returning None (documented pass-through) and CLAIMS it by
        # returning a result. A raised exception is neither — it means a handler started serving the
        # path and crashed. Surface that instead of swallowing it and falling through, which would
        # hand back a later handler's response for the wrong path, or a silent 404 masking a 500.
        for handler in self._web_handlers:
            try:
                result = handler(path)
            except Exception:
                logger.error("web handler for %r crashed", path, exc_info=True)
                raise
            if result is not None:
                return result
        return None

    def serve_request(self, req: PluginRequest) -> PluginResponse | None:
        """Chain request handlers (first non-None wins) — same pass-through semantics as serve_web,
        but for query-param backend requests. Returns a PluginResponse, or None if no handler claimed it.

        A handler that raises has CLAIMED the request and crashed (declining is None) — surface the
        error rather than falling through to a later handler or a silent miss."""
        for handler in self._request_handlers:
            try:
                result = handler(req)
            except Exception:
                logger.error("request handler for %r crashed", req.path, exc_info=True)
                raise
            if result is not None:
                return result
        return None

    def get_startup_hooks(self) -> list[Callable]:
        return self._startup_hooks

    def get_shutdown_hooks(self) -> list[Callable]:
        return self._shutdown_hooks

    # --- SSE --------------------------------------------------------------
    def sse_connect(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=SSE_QUEUE_MAXSIZE)
        try:
            loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            loop = None  # connected outside a running loop (e.g. a test) — push directly
        with self._sse_lock:
            self._sse_clients.append((q, loop))
        return q

    def sse_disconnect(self, q: asyncio.Queue) -> None:
        with self._sse_lock:
            self._sse_clients = [c for c in self._sse_clients if c[0] is not q]

    def push_event(self, event: str, data: str) -> None:
        with self._sse_lock:
            clients = list(self._sse_clients)  # stable snapshot — a concurrent disconnect
            # rebuilds the list, so iterating this copy can't skip a client
        item = (event, data)
        for q, loop in clients:
            if loop is not None:
                # push_event may run on a non-loop thread (handle_signal on the sync threadpool);
                # asyncio.Queue.put_nowait must run on the loop that owns the queue, so hop onto it.
                # _offer runs there too, so the full-queue handling stays on the owning loop.
                loop.call_soon_threadsafe(self._offer, q, item)
            else:
                self._offer(q, item)

    def _offer(self, q: asyncio.Queue, item: tuple[str, str]) -> None:
        """Put an event on one client's bounded queue, dropping its oldest if full.

        Runs on the queue's owning loop (see push_event). A laggard that never reads keeps a
        bounded backlog of the MOST RECENT events instead of growing without limit; a client
        whose queue cannot accept even after a drop is disconnected rather than retried forever.
        """
        try:
            q.put_nowait(item)
        except asyncio.QueueFull:
            try:
                q.get_nowait()  # drop oldest, keep the stream flowing to the latest state
                q.put_nowait(item)
            except Exception:
                logger.warning("dropping unresponsive SSE client (queue full)")
                self.sse_disconnect(q)


@dataclass
class LoadedPlugin:
    manifest: PluginManifest
    path: Path


def _purge_plugin_modules(plugin_dir: Path) -> None:
    """Drop the plugin's OWN already-imported modules from ``sys.modules`` so a re-load picks up
    edited code (hot reload). Only modules whose file lives under ``plugin_dir`` are purged — shared
    and stdlib modules are untouched. Without this, ``bind``/reload re-runs ``setup()`` but Python
    serves the cached sibling submodules (e.g. a plugin's ``btn_backend`` package), which is why a
    code change used to need a full controller restart."""
    try:
        base = plugin_dir.resolve()
    except OSError:
        return
    for name in list(sys.modules):
        mod = sys.modules.get(name)
        f = getattr(mod, "__file__", None)
        if not f:
            continue
        try:
            # Path containment, not a raw string prefix: startswith(str(plugin_dir)) also
            # matches a SIBLING whose name merely starts with this one (foo -> foobar / foo-v2),
            # purging unrelated modules. is_relative_to compares on path boundaries.
            if Path(f).resolve().is_relative_to(base):
                del sys.modules[name]
        except (OSError, KeyError):
            pass


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
            _purge_plugin_modules(
                child
            )  # hot reload: re-import the plugin's own code on every load
            spec = importlib.util.spec_from_file_location(f"rvmc_plugin_{manifest.id}", entry)
            module = importlib.util.module_from_spec(spec)  # type: ignore[arg-type]
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            if not hasattr(module, "setup"):
                logger.error("plugin %r has no setup(registry)", manifest.id)
                continue
            # Transactional load: snapshot the registry, drop this plugin's PRIOR
            # registrations (reload = replace, not accumulate), then run setup(). On a
            # setup() failure, restore the snapshot so a partial/broken load leaves the
            # registry exactly as it was (and a reload keeps the old working version).
            snapshot = registry._snapshot_registrations()
            registry._clear_owner(manifest.id)
            registry._current_owner = manifest.id
            try:
                module.setup(registry)
            except Exception:
                registry._restore_registrations(snapshot)
                raise
            finally:
                registry._current_owner = None
            lp = LoadedPlugin(manifest=manifest, path=child)
            # Replace any prior LoadedPlugin with the same id (reload) rather than
            # appending a duplicate that would later self-conflict in the claim check.
            registry.loaded = [p for p in registry.loaded if p.manifest.id != manifest.id]
            registry.loaded.append(lp)
            loaded.append(lp)
            logger.info("loaded plugin %r v%s", manifest.id, manifest.version)
        except Exception as e:
            logger.error("error loading plugin %r: %s", manifest.id, e, exc_info=True)
    _warn_backend_host_conflicts(registry.loaded)
    return loaded


def _warn_backend_host_conflicts(loaded: list[LoadedPlugin]) -> None:
    """Flag two plugins whose network CLAIMS overlap at bind time, instead of letting
    them collide silently and resolve by manifest-directory sort order. Warn (don't fail): a
    conflict is an operator misconfiguration, not a reason to bring down the whole registry.
    The router (P2) turns this into a hard bind-time error.

    Consults each plugin's ``effective_claims()`` — the explicit ``claims`` (port / proto /
    method / path) when present, else the ``backend_host`` shorthand — via the router's
    ``claims_overlap``. This both catches a plugin that claims extra ports BEYOND its
    backend_host (the old backend_host-only check missed those) and stops falsely flagging
    two plugins that legitimately split the same host by method/path."""
    from ..router.router import claims_overlap  # local: avoid a plugins<->router import cycle

    items = [(lp.manifest.id, lp.manifest.effective_claims()) for lp in loaded]
    for i in range(len(items)):
        pid_a, cs_a = items[i]
        for j in range(i + 1, len(items)):
            pid_b, cs_b = items[j]
            if pid_a == pid_b:
                continue
            hit = next(
                (ca.host for ca in cs_a for cb in cs_b if claims_overlap(ca, cb)),
                None,
            )
            if hit is not None:
                logger.warning(
                    "plugin claim conflict: %r and %r both claim %r; the first-loaded "
                    "(%r) wins by directory order — rename one or narrow the claim",
                    pid_a,
                    pid_b,
                    hit,
                    pid_a,
                )
