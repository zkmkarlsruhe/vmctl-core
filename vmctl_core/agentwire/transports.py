"""Bounded socket pools for TCP, virtio-serial and serial chardev sockets."""

from __future__ import annotations

import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from queue import Empty, LifoQueue
from threading import Lock
from typing import TYPE_CHECKING, Literal

from vmctl_core.agentwire import _va1

if TYPE_CHECKING:
    from vmctl_core.agentwire.client import Hello

Policy = Literal["persistent", "per_call"]


class Connection:
    """One leased stream. The lease serializes its complete request/reply exchange."""

    def __init__(self, sock: socket.socket) -> None:
        self.socket = sock
        self.hello: Hello | None = None
        self.deadline = 0.0
        self.reader = _va1.FrameReader(self._read, 4096)
        self.closed = False

    def _remaining(self) -> float:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("VA1 exchange timed out")
        return remaining

    def _read(self, size: int) -> bytes:
        self.socket.settimeout(self._remaining())
        return self.socket.recv(size)

    def send(self, data: bytes) -> None:
        self.socket.settimeout(self._remaining())
        self.socket.sendall(data)

    def receive(self, ident: bytes) -> _va1.Frame:
        while True:
            try:
                frame = self.reader.next()
            except StopIteration as exc:
                raise ConnectionError("VA1 stream closed") from exc
            if frame[1] == b"BEAT":
                if self.hello is None or "beat" not in self.hello.caps:
                    raise _va1.FrameError("bad_frame", frame[0])
                continue
            if frame[0] != ident or frame[1] not in (b"OK", b"ERR"):
                raise _va1.FrameError("bad_frame", frame[0])
            return frame

    def close(self) -> None:
        self.closed = True
        self.socket.close()


class SocketTransport:
    """A socket factory plus a small pool; every socket negotiates its own hello.

    ``per_call`` closes a lease after one public call (hello and the call share
    that socket). Factory sockets must connect within the supplied timeout.
    """

    def __init__(
        self,
        connect: Callable[[float], socket.socket],
        *,
        policy: Policy = "persistent",
        pool_size: int = 1,
    ) -> None:
        if pool_size < 1 or policy not in ("persistent", "per_call"):
            raise ValueError("invalid pool size or connection policy")
        self.connect = connect
        self.policy = policy
        self._pool: LifoQueue[Connection | None] = LifoQueue(pool_size)
        self._lock = Lock()
        self._closed = False
        for _ in range(pool_size):
            self._pool.put(None)

    @contextmanager
    def connection(self, timeout: float = 30.0) -> Iterator[Connection]:
        deadline = time.monotonic() + timeout
        try:
            conn = self._pool.get(timeout=max(0, timeout))
        except Empty as exc:
            raise TimeoutError("VA1 connection pool exhausted") from exc
        try:
            with self._lock:
                if self._closed:
                    raise RuntimeError("transport is closed")
            if conn is None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("VA1 connection deadline expired")
                conn = Connection(self.connect(remaining))
            conn.deadline = deadline
            yield conn
        except (OSError, _va1.FrameError):
            if conn is not None:
                conn.close()
            raise
        finally:
            with self._lock:
                if conn is not None and (self.policy == "per_call" or self._closed or conn.closed):
                    conn.close()
                    conn = None
                self._pool.put_nowait(conn)

    def close(self) -> None:
        """Close idle sockets now and leased sockets when their calls finish."""
        with self._lock:
            self._closed = True
            idle = []
            while True:
                try:
                    idle.append(self._pool.get_nowait())
                except Empty:
                    break
            for conn in idle:
                if conn is not None:
                    conn.close()
                self._pool.put_nowait(None)

    def __enter__(self) -> SocketTransport:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


class TCPTransport(SocketTransport):
    def __init__(
        self, host: str, port: int = 9009, *, policy: Policy = "persistent", pool_size: int = 1
    ) -> None:
        super().__init__(
            lambda timeout: socket.create_connection((host, port), timeout),
            policy=policy,
            pool_size=pool_size,
        )


class UnixTransport(SocketTransport):
    def __init__(self, path: str, *, policy: Policy = "persistent", pool_size: int = 1) -> None:
        self.path = path

        def connect(timeout: float) -> socket.socket:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.settimeout(timeout)
                sock.connect(path)
            except BaseException:
                sock.close()
                raise
            return sock

        super().__init__(connect, policy=policy, pool_size=pool_size)


def transport_for(
    endpoint: str, *, pool_size: int = 1, policy: Policy = "persistent"
) -> SocketTransport:
    """Parse HOST:PORT, [IPv6]:PORT or unix:PATH. No HTTP transports."""
    if endpoint.startswith("unix:"):
        if not endpoint[5:]:
            raise ValueError("unix socket path is empty")
        return UnixTransport(endpoint[5:], pool_size=pool_size, policy=policy)
    host, separator, port = endpoint.rpartition(":")
    if not separator or not host or "://" in endpoint:
        raise ValueError("expected HOST:PORT or unix:PATH")
    return TCPTransport(
        host.removeprefix("[").removesuffix("]"), int(port), pool_size=pool_size, policy=policy
    )
