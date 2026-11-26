"""Shared VA1 sessions for backend guest-agent sockets."""

from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager, nullcontext
from threading import Lock

from ..agentwire import AgentClient, AgentError, SocketTransport, _va1
from .base import BackendError


class AgentUnreachable(BackendError):
    """No agent reply. ``reached_guest`` is false only if no socket connected.

    A true value is conservative: the tool may have run. VA1 retries within a
    session reuse the request ID; a new public call does not.
    """

    def __init__(self, msg: str, *, reached_guest: bool) -> None:
        super().__init__(msg)
        self.reached_guest = reached_guest


_PORT_LOCKS: dict[str, Lock] = {}
_PORT_LOCKS_GUARD = Lock()


@contextmanager
def agent_session(
    connectors: Sequence[Callable[[float], socket.socket]], *, serial_port: str | None = None
) -> Iterator[AgentClient]:
    """Lease one VA1 stream, rotating lanes on reconnect with the same call ID.

    Close the stream at the end of the operation, including multi-chunk transfers.
    Tool/protocol errors become BackendError; transport failures retain ambiguity.
    Serial sessions sharing a port are exclusive, even across backend objects.
    """
    connected = False
    lane = 0

    def connect(timeout: float) -> socket.socket:
        nonlocal connected, lane
        deadline = time.monotonic() + timeout
        errors = []
        for _ in connectors:
            connector = connectors[lane % len(connectors)]
            lane += 1
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                sock = connector(remaining)
            except (OSError, BackendError) as exc:
                errors.append(str(exc))
                continue
            connected = True
            return sock
        raise OSError("; ".join(errors) or "no agent lane available")

    with _PORT_LOCKS_GUARD:
        port_lock = _PORT_LOCKS.setdefault(serial_port, Lock()) if serial_port else None
    with (
        port_lock if port_lock is not None else nullcontext(),
        SocketTransport(connect) as transport,
    ):
        try:
            yield AgentClient(transport)
        except AgentError as exc:
            raise BackendError(f"agent tool failed: {exc}") from exc
        except (OSError, _va1.FrameError) as exc:
            raise AgentUnreachable(f"agent unreachable: {exc}", reached_guest=connected) from exc
        except (ValueError, KeyError) as exc:
            raise BackendError(f"invalid VA1 exchange: {exc}") from exc
