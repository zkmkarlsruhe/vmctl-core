"""Typed host adapter for the byte-oriented VA1 contract."""

from __future__ import annotations

import base64
import codecs
import math
import secrets
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

from . import _va1
from .images import UnsupportedImageFormat, image_header
from .transports import Connection, SocketTransport

Kind = Literal["-", "rows", "raw"]
Scalar = str | int | float | bool
Arguments = Mapping[str, Scalar | Sequence[Scalar]]
Payload = bytes | list[dict[str, str]] | None


class AgentError(Exception):
    def __init__(self, code: str, msg: str, kv: dict[str, str]) -> None:
        super().__init__(f"{code}: {msg}")
        self.code, self.msg, self.kv = code, msg, kv


class ProtocolError(ValueError):
    """A syntactically valid frame violates the tool/session contract."""


@dataclass(frozen=True)
class Reply:
    kv: dict[str, str]
    kind: str
    payload: Payload

    def numbered(self, prefix: str = "arg") -> list[str]:
        return numbered_list(self.kv, prefix)


def numbered_list(kv: Mapping[str, str], prefix: str = "arg") -> list[str]:
    """Read a contiguous numbered list, rejecting gaps and noncanonical indices."""
    return [
        value.decode("utf-8")
        for value in _va1.numbered_list(
            {key: value.encode("utf-8") for key, value in kv.items()}, prefix
        )
    ]


@dataclass(frozen=True)
class Hello:
    kv: dict[str, str]
    charset: str
    max_frame: int
    tools: frozenset[str]
    caps: frozenset[str]


HELLO_FIELDS = frozenset(
    [
        "agent",
        "version",
        "protocol",
        "os",
        "os_version",
        "arch",
        "cs",
        "max_frame",
        "caps",
        "tools",
        "boot",
        "temp",
    ]
)


def parse_hello(frame: _va1.Frame) -> Hello:
    pairs = dict(frame[2])
    try:
        charset = pairs[b"cs"].decode("ascii")
        codecs.lookup(charset)
        # VA1 delimiters and metadata require an ASCII-compatible text codec.
        if "tool=hello\n".encode(charset) != b"tool=hello\n":
            raise ValueError("charset is not ASCII-compatible")
        kv = {key.decode("ascii"): value.decode(charset) for key, value in pairs.items()}
        maximum = int(kv["max_frame"])
        if not kv.keys() >= HELLO_FIELDS or not kv["protocol"].startswith("1.") or maximum <= 0:
            raise ValueError("invalid hello fields or max_frame")
        float(kv["boot"])
        if not kv["temp"]:
            raise ValueError("empty temp directory")
        if frame[1] != b"OK" or frame[3] != b"-":
            raise ValueError("hello must return OK without a payload")
        return Hello(
            kv,
            charset,
            maximum,
            frozenset(filter(None, kv["tools"].split(","))),
            frozenset(filter(None, kv["caps"].split(","))),
        )
    except (KeyError, LookupError, ValueError) as exc:
        raise ProtocolError(f"invalid hello: {exc}") from exc


def encode_arguments(args: Arguments, charset: str) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for key, value in args.items():
        values = (
            [(key, value)]
            if isinstance(value, (str, int, float, bool))
            else [(f"{key}.{index}", item) for index, item in enumerate(value)]
        )
        for name, item in values:
            if name in result:
                raise ValueError(f"duplicate argument: {name}")
            result[name] = (str(int(item)) if isinstance(item, bool) else str(item)).encode(charset)
    return result


class AgentClient:
    def __init__(
        self,
        transport: SocketTransport,
        *,
        retries: int = 3,
        retry_delay: float = 0.05,
        grace: float = 15.0,
    ) -> None:
        if retries < 0 or retry_delay < 0 or grace < 0:
            raise ValueError("negative retry setting")
        self.transport = transport
        self.retries, self.retry_delay, self.grace = retries, retry_delay, grace

    def _hello(self, conn: Connection, ident: bytes | None = None) -> Hello:
        if conn.hello is None:
            ident = ident or secrets.token_hex(8).encode("ascii")
            conn.send(
                _va1.encode_frame(
                    ident, "CALL", {"tool": b"hello", "host": b"vmctl-core/0.1.0"}, "-", b""
                )
            )
            frame = conn.receive(ident)
            if frame[1] == b"ERR":
                self._decode(frame, "ascii", frozenset())
            try:
                conn.hello = parse_hello(frame)
            except ProtocolError:
                conn.close()
                raise
            conn.reader.max_frame = conn.hello.max_frame
        return conn.hello

    def hello(self, *, timeout: float = 30.0) -> Hello:
        """Return negotiation cached on the leased connection, never globally."""
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be finite and nonnegative")
        ident = secrets.token_hex(8).encode("ascii")
        deadline = time.monotonic() + (timeout + self.grace) * (self.retries + 1)
        failures = 0
        while True:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("VA1 hello retry deadline expired")
                with self.transport.connection(min(timeout + self.grace, remaining)) as conn:
                    return self._hello(conn, ident)
            except AgentError as exc:
                if exc.code != "busy" or time.monotonic() >= deadline:
                    raise
            except (OSError, _va1.FrameError):
                if failures >= self.retries or time.monotonic() >= deadline:
                    raise
                failures += 1
            time.sleep(min(self.retry_delay, max(0, deadline - time.monotonic())))

    @staticmethod
    def _decode(frame: _va1.Frame, charset: str, caps: frozenset[str]) -> Reply:
        kv = {key.decode("ascii"): value.decode(charset) for key, value in frame[2]}
        if frame[1] == b"ERR":
            if "code" not in kv or "msg" not in kv:
                raise ProtocolError("ERR lacks code or msg")
            raise AgentError(kv["code"], kv["msg"], kv)
        kind = frame[3].decode("ascii")
        payload: Payload = None
        if kind == "raw":
            payload = base64.b64decode(frame[4], validate=True) if "b64" in caps else frame[4]
        elif kind == "rows":
            columns, rows = _va1.decode_rows(frame[4])
            names = [column.decode(charset) for column in columns]
            payload = [
                dict(zip(names, (value.decode(charset) for value in row), strict=True))
                for row in rows
            ]
        return Reply(kv, kind, payload)

    def call(
        self,
        tool: str,
        args: Arguments | None = None,
        payload: Payload = None,
        kind: Kind = "-",
        timeout: float = 30.0,
    ) -> Reply:
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("timeout must be finite and nonnegative")
        if args and {"tool", "timeout"} & args.keys():
            raise ValueError("tool and timeout are reserved arguments")
        ident = secrets.token_hex(8).encode("ascii")
        deadline = time.monotonic() + (timeout + self.grace) * (self.retries + 1)
        failures = 0
        while True:
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("VA1 retry deadline expired")
                with self.transport.connection(min(timeout + self.grace, remaining)) as conn:
                    hello = self._hello(conn)
                    kv = encode_arguments(args or {}, hello.charset)
                    kv.update(
                        tool=tool.encode("ascii"), timeout=format(timeout, "g").encode("ascii")
                    )
                    data = self._payload(payload, kind, hello)
                    if len(_va1.encode_kv(kv)) + len(data) > hello.max_frame:
                        raise ValueError("CALL body exceeds max_frame")
                    conn.deadline = min(deadline, time.monotonic() + timeout + self.grace)
                    conn.send(_va1.encode_frame(ident, "CALL", kv, kind, data))
                    frame = conn.receive(ident)
                    if frame[1] == b"ERR" and dict(frame[2]).get(b"code") in (b"crc", b"bad_frame"):
                        # A damaged request is a transport failure, not a tool failure.
                        raise _va1.FrameError(dict(frame[2])[b"code"].decode("ascii"), ident)
                    return self._decode(frame, hello.charset, hello.caps)
            except AgentError as exc:
                if exc.code != "busy":
                    raise
                if time.monotonic() >= deadline:
                    raise
            except (OSError, _va1.FrameError):
                if failures >= self.retries or time.monotonic() >= deadline:
                    raise
                failures += 1
            time.sleep(min(self.retry_delay, max(0, deadline - time.monotonic())))

    @staticmethod
    def _payload(payload: Payload, kind: Kind, hello: Hello) -> bytes:
        if kind == "-" and payload is None:
            return b""
        if kind == "raw" and isinstance(payload, bytes):
            return base64.b64encode(payload) if "b64" in hello.caps else payload
        if kind == "rows" and isinstance(payload, list) and payload:
            columns = list(payload[0])
            if any(set(row) != set(columns) for row in payload):
                raise ValueError("inconsistent row columns")
            return _va1.encode_rows(
                [c.encode(hello.charset) for c in columns],
                [[row[c].encode(hello.charset) for c in columns] for row in payload],
            )
        raise ValueError("payload does not match kind")

    def read_file(self, path: str, *, fork: str = "data", timeout: float = 30.0) -> bytes:
        hello = self.hello(timeout=timeout)
        length = hello.max_frame - 512
        if "b64" in hello.caps:
            length = length // 4 * 3
        if length <= 0:
            raise ValueError("max_frame is too small for read_file")
        data = bytearray()
        size: int | None = None
        while True:
            reply = self.call(
                "read_file",
                {"path": path, "fork": fork, "offset": len(data), "length": length},
                timeout=timeout,
            )
            if not isinstance(reply.payload, bytes):
                raise ProtocolError("read_file did not return raw bytes")
            current_size = int(reply.kv["size"])
            if size is None:
                size = current_size
            if current_size != size or size < len(data) + len(reply.payload):
                raise ProtocolError("read_file size changed during transfer")
            if (
                int(reply.kv["offset"]) != len(data)
                or len(reply.payload) > length
                or reply.kv["eof"] not in ("0", "1")
            ):
                raise ProtocolError("invalid read_file offset, length or eof")
            data.extend(reply.payload)
            if reply.kv["eof"] == "1":
                if int(reply.kv["size"]) != len(data):
                    raise ProtocolError("read_file size changed during transfer")
                return bytes(data)
            if not reply.payload:
                raise ProtocolError("read_file made no progress")

    def write_file(
        self, path: str, data: bytes, *, fork: str = "data", timeout: float = 30.0
    ) -> int:
        hello = self.hello(timeout=timeout)
        offset = 0
        while True:
            args: Arguments = {
                "path": path,
                "fork": fork,
                "offset": offset,
                "truncate": offset == 0,
            }
            kv = encode_arguments(args, hello.charset)
            kv.update(tool=b"write_file", timeout=format(timeout, "g").encode("ascii"))
            length = hello.max_frame - len(_va1.encode_kv(kv))
            if "b64" in hello.caps:
                length = length // 4 * 3
            if length <= 0:
                raise ValueError("write_file metadata exceeds max_frame")
            chunk = data[offset : offset + length]
            reply = self.call("write_file", args, chunk, "raw", timeout)
            if int(reply.kv["written"]) != len(chunk) or int(reply.kv["size"]) != offset + len(
                chunk
            ):
                raise ProtocolError("write_file returned a short write or incorrect size")
            offset += len(chunk)
            if offset == len(data):
                return offset

    def screenshot(
        self, format: str = "png", *, timeout: float = 30.0
    ) -> tuple[str, int, int, bytes]:
        """Read one retained capture, rejecting inconsistent or incomplete pages."""
        hello = self.hello(timeout=timeout)
        length = hello.max_frame - 512
        if "b64" in hello.caps:
            length = length // 4 * 3
        if length <= 0:
            raise ValueError("max_frame is too small for screenshot")
        data = bytearray()
        metadata: tuple[str, str, int, int, int] | None = None
        while True:
            args: dict[str, Scalar] = {"format": format, "offset": len(data), "length": length}
            if metadata is not None:
                args["capture"] = metadata[0]
            reply = self.call("screenshot", args, timeout=timeout)
            if reply.kind != "raw" or not isinstance(reply.payload, bytes):
                raise ProtocolError("screenshot did not return raw bytes")
            try:
                capture, actual_format = reply.kv["capture"], reply.kv["format"]
                width, height = int(reply.kv["width"]), int(reply.kv["height"])
                size, offset = int(reply.kv["size"]), int(reply.kv["offset"])
                eof = reply.kv["eof"]
            except (KeyError, ValueError) as exc:
                raise ProtocolError("invalid screenshot metadata") from exc
            current = (capture, actual_format, width, height, size)
            if not capture or not actual_format or width <= 0 or height <= 0 or size <= 0:
                raise ProtocolError("invalid screenshot capture, format, dimensions or size")
            if metadata is None:
                metadata = current
            elif metadata != current:
                raise ProtocolError("screenshot metadata changed during transfer")
            end = len(data) + len(reply.payload)
            if (
                offset != len(data)
                or len(reply.payload) > length
                or end > size
                or eof not in ("0", "1")
                or (eof == "1") != (end == size)
            ):
                raise ProtocolError("invalid screenshot offset, length or eof")
            if not reply.payload:
                raise ProtocolError("screenshot made no progress")
            data.extend(reply.payload)
            if eof == "1":
                image = bytes(data)
                try:
                    image_header(actual_format, width, height, image)
                except UnsupportedImageFormat:
                    pass
                except ValueError as exc:
                    raise ProtocolError(str(exc)) from exc
                return actual_format, width, height, image
