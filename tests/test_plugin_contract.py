"""The plugin contract is the self-describing authoring surface (plugin_spec): an
AI/human writes a plugin straight from it, so it must stay in lock-step with what the
loader actually accepts. These tests assert it can't silently drift."""

import asyncio
import threading
import time

import pytest

from vmctl_core.plugins import (
    PluginRegistry,
    PluginRequest,
    PluginResponse,
    plugin_spec,
)
from vmctl_core.plugins.contract import _REGISTER_DOCS


def test_every_register_method_is_documented():
    registry_methods = {n for n in dir(PluginRegistry) if n.startswith("register_")}
    assert registry_methods, "no register_* methods found on PluginRegistry"
    missing = registry_methods - set(_REGISTER_DOCS)
    assert not missing, f"register_* methods missing a contract doc: {sorted(missing)}"


def test_plugin_spec_shape():
    spec = plugin_spec()
    assert set(spec) >= {"layout", "manifest_schema", "manifest_example", "registry", "notes"}
    # manifest schema reflects the real PluginManifest fields
    props = spec["manifest_schema"]["properties"]
    assert {"id", "name", "entrypoint", "capabilities"} <= set(props)
    # registry contract covers every register_* method, each with a signature string
    methods = {r["method"] for r in spec["registry"]}
    assert methods == {n for n in dir(PluginRegistry) if n.startswith("register_")}
    for r in spec["registry"]:
        assert r["signature"].startswith(f"registry.{r['method']}(")


def test_serve_request_chains_and_passes_through():
    """A request handler serves a query-param backend request; None passes to the next handler."""
    reg = PluginRegistry()
    reg.register_request_handler(lambda req: None)  # pass-through
    reg.register_request_handler(
        lambda req: (
            PluginResponse(
                body=f"<k m={req.query.get('m')} q={req.query.get('q')} />",
                content_type="application/xml",
            )
            if req.path.endswith("xml.php")
            else None
        )
    )
    req = PluginRequest(
        method="GET",
        path="scripts/xml.php",
        query={"m": "images", "q": "war"},
        headers={},
    )
    resp = reg.serve_request(req)
    assert isinstance(resp, PluginResponse)
    assert resp.content_type == "application/xml"
    assert "m=images" in resp.body and "q=war" in resp.body
    # a path no handler claims -> None
    assert reg.serve_request(PluginRequest("GET", "other", {}, {})) is None


# --- bug 6: a crashing handler is surfaced, not swallowed into a silent 404 ---------------------


def test_serve_web_surfaces_handler_crash():
    """Declining is None (pass-through); a RAISE means a handler claimed the path and crashed.
    serve_web must propagate it — swallowing to None hands back a 404 masking a 500 (or a later
    handler's response for the wrong path)."""
    reg = PluginRegistry()
    reg.register_web_handler(lambda p: None)  # declines cleanly

    def boom(path):
        raise RuntimeError("web handler exploded")

    reg.register_web_handler(boom)
    with pytest.raises(RuntimeError, match="exploded"):
        reg.serve_web("/anything")

    # nothing crashing -> pass-through still yields None, unchanged
    ok = PluginRegistry()
    ok.register_web_handler(lambda p: None)
    assert ok.serve_web("/x") is None


def test_serve_request_surfaces_handler_crash():
    reg = PluginRegistry()

    def boom(req):
        raise RuntimeError("request handler exploded")

    reg.register_request_handler(boom)
    with pytest.raises(RuntimeError, match="exploded"):
        reg.serve_request(PluginRequest("GET", "scripts/xml.php", {}, {}))


# --- bug 5: SSE push from a non-loop thread must wake the loop waiter, and snapshot the client
#            list so a concurrent disconnect can't make an in-flight push skip a survivor --------


def test_push_event_from_worker_thread_wakes_loop_waiter():
    """handle_signal runs on FastAPI's sync threadpool and calls push_event; the SSE queue is owned
    by the event loop. A bare put_nowait() from another thread appends but never wakes the awaiting
    get() (call_soon isn't threadsafe) — the stream hangs. call_soon_threadsafe fixes it."""

    async def main():
        q = reg.sse_connect()  # captures the running loop
        armed = threading.Event()
        pushed_at: list[float] = []

        def worker():
            # Push only AFTER the loop is parked in q.get() (armed + sleep guarantees get() is in the
            # selector). A bare put_nowait from this thread does place the item AND set the waiter's
            # result — but via loop.call_soon, which is NOT threadsafe and does NOT interrupt the
            # selector. So the item is delivered only when the loop next wakes for some OTHER reason
            # (here: the wait_for timeout timer, ~3s later). Assert on LATENCY, not just delivery:
            # call_soon_threadsafe wakes the selector immediately (well under 0.5s).
            armed.wait(2.0)
            time.sleep(0.1)
            pushed_at.append(time.monotonic())
            reg.push_event("signal", "hi")

        threading.Thread(target=worker).start()
        armed.set()  # we are about to await get() with an empty queue
        item = await asyncio.wait_for(q.get(), timeout=3.0)
        return item, time.monotonic() - pushed_at[0]

    reg = PluginRegistry()
    (event, data), latency = asyncio.run(main())
    assert (event, data) == ("signal", "hi")
    assert latency < 0.5, f"cross-thread push took {latency:.2f}s to wake the loop waiter"


def test_push_event_snapshots_against_concurrent_disconnect():
    """A concurrent sse_disconnect() rebuilds the client list; iterating a live list mid-push could
    skip a survivor. push_event iterates a locked snapshot, so every client that stays connected
    receives every event."""
    reg = PluginRegistry()
    qs = [reg.sse_connect() for _ in range(5)]  # no running loop -> loop=None, direct put_nowait
    barrier = threading.Barrier(2)

    def pusher():
        barrier.wait()
        for i in range(200):
            reg.push_event("e", str(i))

    def dropper():
        barrier.wait()
        reg.sse_disconnect(qs[0])  # churn the list while pusher iterates it

    p = threading.Thread(target=pusher)
    d = threading.Thread(target=dropper)
    p.start()
    d.start()
    p.join()
    d.join()

    # survivors were never disconnected, so the snapshot can't skip them: each got all 200
    for q in qs[1:]:
        assert q.qsize() == 200
