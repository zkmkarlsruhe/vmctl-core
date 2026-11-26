"""SSE backlog is bounded per client (ported from the exhibition controller).

An exhibition browser tab that stops reading — a sleeping kiosk, a wedged frontend — used
to grow its event queue without bound over a run of weeks. The queue is capped; when it is
full the OLDEST event is dropped, because the newest state is what a display needs.
"""

import asyncio

from vmctl_core.plugins.runtime import SSE_QUEUE_MAXSIZE, PluginRegistry


def test_queue_is_capped_and_keeps_the_newest_events():
    reg = PluginRegistry()
    q = reg.sse_connect()  # no running loop -> pushes go direct
    for i in range(SSE_QUEUE_MAXSIZE + 50):
        reg.push_event("tick", str(i))

    assert q.qsize() == SSE_QUEUE_MAXSIZE
    # the oldest 50 were dropped, the newest survived
    assert q.get_nowait() == ("tick", "50")
    drained = [q.get_nowait() for _ in range(q.qsize())]
    assert drained[-1] == ("tick", str(SSE_QUEUE_MAXSIZE + 49))


def test_a_reading_client_sees_every_event():
    reg = PluginRegistry()
    q = reg.sse_connect()
    for i in range(10):
        reg.push_event("tick", str(i))
    assert [q.get_nowait()[1] for _ in range(10)] == [str(i) for i in range(10)]


def test_disconnect_stops_delivery():
    reg = PluginRegistry()
    q = reg.sse_connect()
    reg.sse_disconnect(q)
    reg.push_event("tick", "1")
    assert q.empty()


def test_push_from_another_thread_reaches_the_queue():
    """push_event runs on the sync threadpool (handle_signal); the drop-oldest handling has
    to be marshalled onto the queue's own loop, not executed on the calling thread."""

    async def scenario():
        reg = PluginRegistry()
        q = reg.sse_connect()  # captures the running loop
        await asyncio.to_thread(reg.push_event, "tick", "from-thread")
        return await asyncio.wait_for(q.get(), timeout=2)

    assert asyncio.run(scenario()) == ("tick", "from-thread")
