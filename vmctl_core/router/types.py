"""Router primitives — hosting-agnostic (imported by BOTH controllers).

A ``Flow`` is one normalized guest egress. A ``Rung`` is a handler that can ``can_handle`` a
flow and ``handle`` it to one of three outcomes:

* ``Handled(response)`` — this rung answered; stop the ladder.
* ``Terminal(status)`` — this rung OWNS the flow but has no answer (e.g. 404). Stop the ladder;
  do NOT fall through to a lower rung. This is the decline-vs-negative distinction a plugin
  needs so an owned-but-absent request never silently gets archive/live content.
* ``DECLINE`` — not mine; try the next rung.

Rung 0 is the plugin (first refusal); rungs 1..N are proxies (wbc archive, live, …). The router
is only the DECISION — where a rung's ``handle`` gets its bytes (in-process serve_request, an
HTTP proxy call, a WARC read) is the rung's own business, kept out of core.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class Flow:
    """One normalized guest egress flow offered to the ladder."""

    proto: str  # "http" | "https" | "tcp" | "udp"
    dst_host: str  # hostname or IP the guest addressed
    dst_port: int
    method: str | None = None  # HTTP method (None for non-HTTP)
    path: str | None = None  # request path incl. query (None for non-HTTP)
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    guest_ip: str | None = None  # source (for guest->project mapping)
    pid: str | None = None  # resolved project id

    @property
    def tls(self) -> bool:
        return self.proto == "https" or self.dst_port == 443


@dataclass
class Handled:
    """A rung answered the flow. ``response`` is rung-defined (bytes, an object, …)."""

    response: Any


@dataclass
class Terminal:
    """A rung owns the flow but has no answer — stop the ladder (no fall-through)."""

    status: int = 404
    response: Any | None = None


class _Decline:
    """Singleton: 'not mine, try the next rung.'"""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - trivial
        return "DECLINE"


DECLINE = _Decline()

# What a rung's handle() may return.
Outcome = Handled | Terminal | _Decline


@runtime_checkable
class Rung(Protocol):
    """A ladder rung. ``name`` is for logging/audit."""

    name: str

    def can_handle(self, flow: Flow) -> bool: ...

    def handle(self, flow: Flow) -> Outcome: ...
