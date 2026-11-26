"""In-memory VA1 reference agent for tests and guest-port development.

No tool touches the host filesystem, processes, display or power state. One
ReplyCache belongs to the process and is shared by every served connection.
"""

from __future__ import annotations

import base64
import binascii
import posixpath
import secrets
import socket
import struct
import threading
import time
import zlib
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import Literal

from . import _va1
from .client import AgentError

REQUIRED_TOOLS = frozenset(
    [
        "hello",
        "ping",
        "list_dir",
        "stat",
        "read_file",
        "write_file",
        "delete",
        "make_dir",
        "list_processes",
        "kill_process",
        "run_app",
        "open_document",
        "screenshot",
        "send_keys",
        "mouse",
        "shutdown",
        "restart",
    ]
)
OPTIONAL_TOOLS = frozenset(
    [
        "run_shell",
        "run_script",
        "list_windows",
        "window_action",
        "pixel",
        "list_resolutions",
        "set_resolution",
        "win.reg_read",
        "win.reg_write",
        "win.install_from_cd",
        "mac.set_finfo",
        "mac.make_alias",
        "mac.apple_event",
        "mac.set_depth",
        "mac.reassemble_forks",
    ]
)
CATALOG = REQUIRED_TOOLS | OPTIONAL_TOOLS
DEFAULT_TOOLS = REQUIRED_TOOLS | {
    "run_shell",
    "run_script",
    "list_windows",
    "pixel",
    "list_resolutions",
}


@dataclass
class Fault:
    kind: Literal["garbage", "bad_crc", "slow", "drop"]
    tool: str
    delay: float = 0.2


def _png() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack("!I", len(data))
            + kind
            + data
            + struct.pack("!I", binascii.crc32(kind + data))
        )

    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!2I5B", 32, 32, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress((b"\0" + bytes(range(96))) * 32, level=0))
        + chunk(b"IEND", b"")
    )


class FakeAgent:
    def __init__(
        self,
        *,
        charset: str = "utf-8",
        max_frame: int = 4096,
        tools: frozenset[str] = DEFAULT_TOOLS,
        caps: frozenset[str] = frozenset(),
        temp: str = "/tmp",
    ) -> None:
        self.charset, self.max_frame, self.tools, self.caps = charset, max_frame, tools, caps
        self.files: dict[str, bytes] = {}
        self.temp = temp
        self.directories = {"/", temp}
        self.screenshot = ("png", 32, 32, _png())
        self._capture: tuple[str, tuple[str, int, int, bytes]] | None = None
        self.processes: dict[int, str] = {1: "init"}
        self.cache = _va1.ReplyCache()
        self.calls: list[tuple[bytes, str, dict[str, str]]] = []
        self.executions: Counter[str] = Counter()
        self.faults: list[Fault] = []
        self.lock = threading.Lock()
        self._sockets: set[socket.socket] = set()
        self._threads: list[threading.Thread] = []
        self.boot = time.time()

    def inject(
        self,
        kind: Literal["garbage", "bad_crc", "slow", "drop"],
        *,
        tool: str = "ping",
        delay: float = 0.2,
    ) -> None:
        """Inject once on the next new invocation of tool (never on replay)."""
        with self.lock:
            self.faults.append(Fault(kind, tool, delay))

    def _reply(
        self, ident: bytes, kv: dict[str, str], kind: str = "-", payload: bytes = b""
    ) -> bytes:
        if kind == "raw" and "b64" in self.caps:
            payload = base64.b64encode(payload)
        values = {key: value.encode(self.charset) for key, value in kv.items()}
        if len(_va1.encode_kv(values)) + len(payload) > self.max_frame:
            return _va1.error_frame(ident, "too_large", b"reply exceeds max_frame")
        return _va1.encode_frame(ident, "OK", values, kind, payload)

    def _rows(self, ident: bytes, columns: list[str], rows: list[list[str]]) -> bytes:
        return self._reply(
            ident,
            {},
            "rows",
            _va1.encode_rows(
                [column.encode(self.charset) for column in columns],
                [[value.encode(self.charset) for value in row] for row in rows],
            ),
        )

    @staticmethod
    def _error(code: str, msg: str) -> None:
        raise AgentError(code, msg, {})

    def _tool(
        self, ident: bytes, tool: str, args: dict[str, str], kind: bytes, payload: bytes
    ) -> bytes:
        if tool not in self.tools:
            self._error("unsupported" if tool in CATALOG else "unknown_tool", tool)
        if tool == "hello":
            return self._reply(
                ident,
                {
                    "agent": "reference",
                    "version": "1",
                    "protocol": "1.1",
                    "os": "linux",
                    "os_version": "reference",
                    "arch": "python",
                    "cs": self.charset,
                    "max_frame": str(self.max_frame),
                    "caps": ",".join(sorted(self.caps)),
                    "tools": ",".join(sorted(self.tools)),
                    "boot": str(int(self.boot)),
                    "temp": self.temp,
                },
            )
        if tool == "ping":
            return self._reply(
                ident,
                {
                    "t": str(int(time.time())),
                    "uptime": str(int(time.time() - self.boot)),
                    "load": "",
                },
            )
        if tool in ("run_shell", "run_script"):
            return self._reply(
                ident,
                {
                    "exit": "0",
                    "stdout": args.get("cmd", args.get("code", "")),
                    "stderr": "",
                    "truncated": "0",
                },
            )
        # Tools hold this lock only for short in-memory operations. Ping never takes it.
        with self.lock:
            if tool == "screenshot":
                maximum = self.max_frame - 512
                if "b64" in self.caps:
                    maximum = maximum // 4 * 3
                offset, length = int(args.get("offset", "0")), int(args.get("length", maximum))
                if offset < 0 or length <= 0 or length > maximum:
                    self._error("bad_args", "invalid screenshot range")
                if "capture" not in args:
                    self._capture = (secrets.token_hex(8), self.screenshot)
                elif self._capture is None or args["capture"] != self._capture[0]:
                    self._error("not_found", "capture no longer retained")
                assert self._capture is not None
                capture, (format, width, height, data) = self._capture
                return self._reply(
                    ident,
                    {
                        "format": format,
                        "width": str(width),
                        "height": str(height),
                        "size": str(len(data)),
                        "capture": capture,
                        "offset": str(offset),
                        "eof": str(int(offset + length >= len(data))),
                    },
                    "raw",
                    data[offset : offset + length],
                )
            path = args.get("path", "")
            if tool in {
                "list_dir",
                "stat",
                "read_file",
                "write_file",
                "delete",
                "make_dir",
                "run_app",
                "open_document",
            }:
                if not path.startswith("/"):
                    self._error("bad_args", "absolute path required")
                path = posixpath.normpath(path)
            if tool == "make_dir":
                if path in self.directories or path in self.files:
                    self._error("exists", path)
                if posixpath.dirname(path) not in self.directories:
                    self._error("not_found", path)
                self.directories.add(path)
            elif tool == "write_file":
                if kind != b"raw" or args.get("fork", "data") != "data":
                    self._error("bad_args", "raw data fork required")
                if posixpath.dirname(path) not in self.directories:
                    self._error("not_found", path)
                if path in self.directories:
                    self._error("denied", path)
                offset = int(args.get("offset", "0"))
                if offset < 0 or args.get("truncate", "0") not in ("0", "1"):
                    self._error("bad_args", "invalid offset or truncate")
                data = b"" if args.get("truncate") == "1" else self.files.get(path, b"")
                data = data.ljust(offset, b"\0")
                self.files[path] = data[:offset] + payload + data[offset + len(payload) :]
                return self._reply(
                    ident, {"written": str(len(payload)), "size": str(len(self.files[path]))}
                )
            elif tool in ("stat", "read_file", "open_document", "run_app"):
                if path not in self.files and path not in self.directories:
                    self._error("not_found", path)
                data = self.files.get(path, b"")
                if tool == "stat":
                    return self._reply(
                        ident,
                        {
                            "type": "d" if path in self.directories else "f",
                            "size": str(len(data)),
                            "mtime": "0",
                        },
                    )
                if tool == "read_file":
                    offset, length = int(args.get("offset", "0")), int(args["length"])
                    if (
                        offset < 0
                        or not 0 <= length <= self.max_frame - 512
                        or args.get("fork", "data") != "data"
                    ):
                        self._error("bad_args", "invalid read range or fork")
                    return self._reply(
                        ident,
                        {
                            "size": str(len(data)),
                            "offset": str(offset),
                            "eof": str(int(offset + length >= len(data))),
                        },
                        "raw",
                        data[offset : offset + length],
                    )
                if tool == "run_app":
                    _va1.numbered_list(
                        {key: value.encode(self.charset) for key, value in args.items()}
                    )
                    pid = max(self.processes, default=0) + 1
                    self.processes[pid] = path
                    return self._reply(ident, {"pid": str(pid)})
            elif tool == "delete":
                if path in self.files:
                    del self.files[path]
                elif path in self.directories:
                    if any(
                        p.startswith(path.rstrip("/") + "/")
                        for p in self.files.keys() | self.directories
                    ):
                        self._error("denied", "directory not empty")
                    self.directories.remove(path)
                else:
                    self._error("not_found", path)
            elif tool == "list_dir":
                if path not in self.directories:
                    self._error("not_found", path)
                return self._rows(
                    ident,
                    ["name", "type", "size", "mtime"],
                    [
                        [
                            posixpath.basename(p),
                            "d" if p in self.directories else "f",
                            str(len(self.files.get(p, b""))),
                            "0",
                        ]
                        for p in sorted(self.files.keys() | self.directories)
                        if p != path and posixpath.dirname(p) == path
                    ],
                )
            elif tool == "list_processes":
                return self._rows(
                    ident,
                    ["pid", "name"],
                    [[str(pid), name] for pid, name in self.processes.items()],
                )
            elif tool == "kill_process":
                if not {"pid", "name"} & args.keys():
                    self._error("bad_args", "pid or name required")
                matches = [
                    pid
                    for pid, name in self.processes.items()
                    if str(pid) == args.get("pid") or name == args.get("name")
                ]
                for pid in matches:
                    del self.processes[pid]
                return self._reply(ident, {"killed": str(len(matches))})
            elif tool == "list_windows":
                return self._rows(ident, ["id", "title", "app", "x", "y", "w", "h", "visible"], [])
            elif tool == "list_resolutions":
                return self._rows(ident, ["w", "h", "depth"], [["1", "1", "24"]])
            elif tool == "pixel":
                return self._reply(ident, {"r": "0", "g": "0", "b": "0"})
            elif tool in ("send_keys", "mouse", "shutdown", "restart"):
                pass
            else:
                self._error("unsupported", tool)
        return self._reply(ident, {})

    def serve(self, sock: socket.socket) -> None:
        """Serve one owned socket until EOF; also works with socket.socketpair()."""
        reader = _va1.FrameReader(sock.recv, 4096)
        negotiated = False
        try:
            while True:
                try:
                    ident, frame_type, pairs, kind, payload = reader.next()
                except StopIteration:
                    return
                except _va1.FrameError as exc:
                    if exc.id is not None:
                        sock.sendall(_va1.error_frame(exc.id, exc.code, b"invalid frame"))
                    continue
                if frame_type != b"CALL":
                    sock.sendall(_va1.error_frame(ident, "bad_frame", b"expected CALL"))
                    continue
                try:
                    args = {key.decode("ascii"): value.decode(self.charset) for key, value in pairs}
                    tool = args.pop("tool")
                except (KeyError, UnicodeError):
                    sock.sendall(_va1.error_frame(ident, "bad_frame", b"invalid tool or text"))
                    continue
                if not negotiated and tool != "hello":
                    sock.sendall(_va1.error_frame(ident, "bad_args", b"hello required first"))
                    continue
                with self.lock:
                    self.calls.append((ident, tool, args))
                    state, reply = self.cache.begin(ident)
                    faults = []
                    if state == "new":
                        faults = [f for f in self.faults if f.tool == tool]
                        self.faults = [f for f in self.faults if f.tool != tool]
                        self.executions[tool] += 1
                if state == "busy":
                    reply = _va1.error_frame(ident, "busy", b"call is running")
                elif state == "new":
                    try:
                        delay = max((f.delay for f in faults if f.kind == "slow"), default=0)
                        # Safe sleep commands used by conformance; no host command is executed.
                        if tool in ("run_script", "run_shell") and (
                            "sleep" in args.get("code", "") or args.get("cmd") == "sleep 1"
                        ):
                            delay = max(delay, 1.0)
                        timeout = float(args.get("timeout", "30"))
                        time.sleep(max(0, min(delay, timeout)))
                        if delay > timeout:
                            self._error("timeout", "tool deadline exceeded")
                        if kind == b"raw" and "b64" in self.caps:
                            payload = base64.b64decode(payload, validate=True)
                        reply = self._tool(ident, tool, args, kind, payload)
                    except AgentError as exc:
                        reply = _va1.error_frame(ident, exc.code, exc.msg.encode(self.charset))
                    except (KeyError, ValueError, _va1.FrameError) as exc:
                        reply = _va1.error_frame(
                            ident, "bad_args", str(exc).encode(self.charset, "replace")
                        )
                    except Exception as exc:
                        reply = _va1.error_frame(
                            ident, "internal", str(exc).encode(self.charset, "replace")
                        )
                    with self.lock:
                        self.cache.finish(ident, reply)
                assert reply is not None
                if tool == "hello" and state != "busy":
                    negotiated = True
                    reader.max_frame = self.max_frame
                if any(f.kind == "drop" for f in faults):
                    return
                if any(f.kind == "garbage" for f in faults):
                    sock.sendall(b"garbage\x00\xff\x02VA")
                if any(f.kind == "bad_crc" for f in faults):
                    header, body = reply.split(b"\n", 1)
                    fields = header.split(b" ")
                    fields[-1] = f"{int(fields[-1], 16) ^ 1:08x}".encode()
                    reply = b" ".join(fields) + b"\n" + body
                sock.sendall(reply)
        except OSError:
            pass
        finally:
            sock.close()
            with self.lock:
                self._sockets.discard(sock)

    def start(self, sock: socket.socket) -> threading.Thread:
        thread = threading.Thread(target=self.serve, args=(sock,), daemon=True)
        with self.lock:
            self._sockets.add(sock)
            self._threads.append(thread)
        thread.start()
        return thread

    def connect(self, timeout: float) -> socket.socket:
        """SocketTransport factory; each lease opens a fresh socketpair stream."""
        client, server = socket.socketpair()
        client.settimeout(timeout)
        self.start(server)
        return client

    def close(self) -> None:
        with self.lock:
            sockets, threads = list(self._sockets), list(self._threads)
        for sock in sockets:
            with suppress(OSError):
                sock.shutdown(socket.SHUT_RDWR)
            sock.close()
        for thread in threads:
            thread.join(timeout=2)

    @contextmanager
    def listen(self, path: str | None = None, *, one_stream: bool | None = None) -> Iterator[str]:
        """Temporary listener; Unix sockets default to one active stream per port."""
        if one_stream is None:
            one_stream = path is not None
        listener = socket.socket(socket.AF_UNIX if path else socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(path if path else ("127.0.0.1", 0))
            listener.listen()
        except BaseException:
            listener.close()
            raise
        listener.settimeout(0.05)
        stopped = threading.Event()

        def accept() -> None:
            worker: threading.Thread | None = None
            while not stopped.is_set():
                try:
                    sock, _ = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    return
                if one_stream and worker is not None and worker.is_alive():
                    sock.close()
                else:
                    worker = self.start(sock)

        thread = threading.Thread(target=accept, daemon=True)
        thread.start()
        try:
            yield "unix:" + path if path else f"127.0.0.1:{listener.getsockname()[1]}"
        finally:
            stopped.set()
            listener.close()
            thread.join(timeout=2)
            self.close()
            if path:
                from pathlib import Path

                Path(path).unlink(missing_ok=True)
