"""The handle a GuestOS module operates through.

A module never imports the controller. Instead the controller hands it a
``GuestContext`` — a thin, backend-agnostic facade over the things a module needs:
the per-tool guest-agent call (``guest_call``), file push/pull, the resolved base
image (so a module can read its own ``os`` label / hardware hints), and the
hypervisor-level CD insert/eject (for the universal datalink + driver discs, which
work even on a guest with no agent).

Keeping this an explicit, narrow object (rather than passing the whole Controller)
is what makes a module a pure strategy: trivially unit-testable with a fake context,
and identical in research and exhibition controllers.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol

from ..agentwire import Reply
from ..catalog import BaseImage


class GuestContext(Protocol):
    """What a GuestOS module is allowed to do to a single running instance."""

    instance_id: str
    base: BaseImage

    def guest_call(self, tool: str, *, timeout: float = 30.0, **args: Any) -> Reply:
        """Invoke a VA1 tool and return Reply (kv, rows or raw bytes).
        Raises if the guest has no reachable agent — guard with the AGENT capability."""

    def guest_write_file(self, path: str, data: bytes) -> None: ...
    def guest_read_file(self, path: str) -> bytes: ...

    # hypervisor-level, no agent required:
    def insert_cd(self, iso_path: str) -> None: ...
    def eject_cd(self) -> None: ...
    def send_key(self, keys: list[str]) -> None: ...


# A factory the controller registers so modules stay decoupled from how a context
# is actually built. Optional sugar — modules receive a ready-made GuestContext.
GuestContextFactory = Callable[[str], GuestContext]

_factory: GuestContextFactory | None = None


def set_context_factory(fn: GuestContextFactory) -> None:
    global _factory
    _factory = fn


def context_for(instance_id: str) -> GuestContext:
    if _factory is None:
        raise RuntimeError("no GuestContext factory registered (controller wiring missing)")
    return _factory(instance_id)
