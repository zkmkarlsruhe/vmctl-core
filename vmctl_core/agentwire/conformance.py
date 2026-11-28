"""Non-destructive VA1 section 8 checks, suitable for golden acceptance.

Usage: python -m vmctl_core.agentwire.conformance HOST:PORT|unix:PATH [--scratch DIR]
Add --second unix:PATH for cross-stream checks through a separate serial port.
DIR defaults to hello temp; the runner creates a unique child and removes
only that child and its own files. Power, input, process killing and arbitrary
OS-specific mutations are reported as SKIP, never invoked on a live guest.
"""

from __future__ import annotations

import argparse
import ntpath
import posixpath
import secrets
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing, contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from vmctl_core.agentwire import _va1
from vmctl_core.agentwire.client import AgentClient, AgentError, Arguments, Hello, encode_arguments
from vmctl_core.agentwire.fakeagent import CATALOG, REQUIRED_TOOLS
from vmctl_core.agentwire.images import UnsupportedImageFormat, image_header
from vmctl_core.agentwire.transports import Connection, TCPTransport, UnixTransport, transport_for


@dataclass(frozen=True)
class Check:
    name: str
    status: Literal["PASS", "FAIL", "SKIP"]
    detail: str = ""


class SkipCheck(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _join(parent: str, name: str) -> str:
    if "\\" in parent or (len(parent) >= 2 and parent[1] == ":"):
        return ntpath.join(parent, name)
    if ":" in parent and "/" not in parent:
        return parent.rstrip(":") + ":" + name
    return posixpath.join(parent, name)


def _wire(ident: bytes, tool: str, hello: Hello, args: Arguments | None = None) -> bytes:
    kv = encode_arguments(args or {}, hello.charset)
    kv["tool"] = tool.encode("ascii")
    return _va1.encode_frame(ident, "CALL", kv, "-", b"")


def run(
    client: AgentClient, scratch: str | None = None, *, second: AgentClient | None = None
) -> list[Check]:
    """Return one result per check; failures never prevent scratch cleanup."""
    checks: list[Check] = []

    def check(name: str, action: Callable[[], object]) -> None:
        try:
            action()
        except (SkipCheck, UnsupportedImageFormat) as exc:
            checks.append(Check(name, "SKIP", str(exc)))
        except Exception as exc:
            checks.append(
                Check(name, "FAIL", str(exc) or repr(exc))
            )  # TimeoutError() has no message
        else:
            checks.append(Check(name, "PASS"))

    try:
        hello = client.hello(timeout=5)
    except Exception as exc:
        return [Check("hello fields and charset", "FAIL", str(exc))]
    check(
        "hello fields and charset",
        lambda: require(
            hello.tools >= REQUIRED_TOOLS,
            "required tools missing: " + ", ".join(sorted(REQUIRED_TOOLS - hello.tools)),
        ),
    )

    def expected_error(tool: str, code: str) -> None:
        try:
            client.call(tool, timeout=5)
        except AgentError as exc:
            require(exc.code == code, f"expected {code}, got {exc.code}")
        else:
            raise ValueError(f"expected {code}, got OK")

    check(
        "unknown_tool",
        lambda: expected_error("va1_conformance_unknown_" + secrets.token_hex(4), "unknown_tool"),
    )
    absent = sorted(CATALOG - hello.tools)
    if absent:
        check("unsupported", lambda: expected_error(absent[0], "unsupported"))
    else:
        checks.append(Check("unsupported", "SKIP", "all catalog tools advertised"))

    @contextmanager
    def primary() -> Iterator[Connection]:
        with client.transport.connection(10) as conn:
            client._hello(conn)
            yield conn

    @contextmanager
    def other_stream() -> Iterator[Connection]:
        if second is not None:
            require(
                second.transport is not client.transport, "second must use a separate transport"
            )
            if isinstance(client.transport, UnixTransport) and isinstance(
                second.transport, UnixTransport
            ):
                require(
                    Path(client.transport.path).resolve() != Path(second.transport.path).resolve(),
                    "second Unix stream must use a different socket path",
                )
            with second.transport.connection(10) as conn:
                second._hello(conn)
                yield conn
        elif isinstance(client.transport, TCPTransport):
            with closing(Connection(client.transport.connect(5))) as conn:
                conn.deadline = time.monotonic() + 10
                client._hello(conn)
                yield conn
        else:
            raise SkipCheck(
                "cross-stream checks require TCP or --second unix:PATH for a separate port; "
                "a Unix serial port has only one stream"
            )

    def stream_recovery(corrupt: bool) -> None:
        with primary() as conn:
            assert conn.hello is not None
            ident = secrets.token_hex(8).encode()
            wire = _wire(ident, "ping", conn.hello)
            if corrupt:
                header, body = wire.split(b"\n", 1)
                fields = header.split(b" ")
                fields[-1] = f"{int(fields[-1], 16) ^ 1:08x}".encode()
                conn.send(b" ".join(fields) + b"\n" + body)
                frame = conn.receive(ident)
                require(
                    frame[1] == b"ERR" and dict(frame[2]).get(b"code") == b"crc",
                    "CRC was not rejected",
                )
            else:
                conn.send(b"garbage\x00\xff\x02VA")
            conn.send(wire)
            require(conn.receive(ident)[1] == b"OK", "good frame after corruption failed")

    check("CRC then good frame on same stream", lambda: stream_recovery(True))
    check("garbage before frame", lambda: stream_recovery(False))

    def replay() -> None:
        ident = secrets.token_hex(8).encode()
        with other_stream() as observer, primary() as conn:
            assert conn.hello is not None
            conn.send(_wire(ident, "ping", conn.hello))
            original = conn.receive(ident)
            assert observer.hello is not None
            # The ID alone is identity, even if the retry body differs.
            observer.send(_wire(ident, "va1_conformance_unknown", observer.hello))
            require(observer.receive(ident) == original, "stored reply changed across streams")

    check("stored reply replay across streams", replay)

    def running() -> None:
        if "run_shell" in hello.tools and hello.kv["os"].lower() in (
            "linux",
            "darwin",
            "macosx",
            "freebsd",
            "netbsd",
            "openbsd",
        ):
            tool, args = "run_shell", {"cmd": "sleep 1", "timeout": "15"}
        elif "run_script" in hello.tools:
            tool, args = (
                "run_script",
                # 15 s: a fresh Win11 needs over 2 s to start the child interpreter (live, 2026-11-27)
                {"lang": "python", "code": "import time; time.sleep(1)", "timeout": "15"},
            )
        else:
            raise SkipCheck("no safe slow tool advertised")
        with other_stream() as observer, primary() as worker:
            assert worker.hello is not None and observer.hello is not None
            ident = secrets.token_hex(8).encode()
            worker.send(_wire(ident, tool, worker.hello, args))
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(worker.receive, ident)
                time.sleep(0.1)
                if future.done():
                    frame = future.result()
                    if frame[1] == b"ERR" and dict(frame[2]).get(b"code") == b"internal":
                        raise ValueError("slow tool returned internal")
                    raise SkipCheck("guest has no supported safe one-second sleep")
                observer.send(_wire(ident, tool, observer.hello, args))
                busy = observer.receive(ident)
                require(
                    busy[1] == b"ERR" and dict(busy[2]).get(b"code") == b"busy",
                    "running duplicate did not return busy",
                )
                ping_id = secrets.token_hex(8).encode()
                observer.send(_wire(ping_id, "ping", observer.hello))
                require(
                    observer.receive(ping_id)[1] == b"OK" and not future.done(),
                    "ping waited for running tool",
                )
                reply = future.result(timeout=20)
                require(reply[1] == b"OK", "slow tool failed")
                observer.send(_wire(ident, tool, observer.hello, args))
                require(observer.receive(ident) == reply, "completed slow call did not replay")

    check("busy and ping during running call", running)

    owned_files: list[str] = []
    directory: str | None = None
    if scratch is None:
        scratch = hello.kv["temp"]

    def make_scratch() -> None:
        nonlocal directory
        if scratch is None:
            raise SkipCheck("supply --scratch with an existing native guest directory")
        candidate = _join(scratch, "va1-" + secrets.token_hex(8))
        client.call("make_dir", {"path": candidate}, timeout=5)
        directory = candidate

    check("create scratch directory", make_scratch)

    def file_roundtrip(name: str, data: bytes) -> None:
        if directory is None:
            raise SkipCheck("scratch directory unavailable")
        path = _join(directory, name)
        owned_files.append(path)
        client.write_file(path, data, timeout=5)
        require(client.read_file(path, timeout=5) == data, "file bytes changed")

    try:
        check("all 256 byte values", lambda: file_roundtrip("bytes", bytes(range(256))))

        def high_name() -> None:
            for character in ("é", "ä", "ø", "ü"):
                try:
                    encoded = character.encode(hello.charset)
                except UnicodeError:
                    continue
                if any(value > 127 for value in encoded):
                    file_roundtrip("name-" + character, b"text\r\n\x00\xff")
                    return
            raise SkipCheck("charset cannot encode a high-byte filename")

        check("filename with bytes above 0x7F", high_name)
        check(
            "chunked file larger than max_frame",
            lambda: file_roundtrip("large", bytes(range(256)) * (hello.max_frame // 256 + 3)),
        )
        check("screenshot image header", lambda: image_header(*client.screenshot(timeout=5)))

        safe: dict[str, Arguments] = {
            "hello": {"host": "vmctl-core/conformance"},
            "ping": {},
            "list_processes": {},
            "screenshot": {"format": "png"},
            "list_windows": {},
            "list_resolutions": {},
            "pixel": {"x": 0, "y": 0},
        }
        if directory is not None:
            safe.update(
                list_dir={"path": directory},
                stat={"path": directory},
                read_file={
                    "path": _join(directory, "bytes"),
                    "length": min(256, hello.max_frame - 512),
                },
            )
        exercised = (
            {"make_dir", "write_file", "read_file", "delete"} if directory is not None else set()
        )
        for tool in sorted(hello.tools):

            def probe(tool: str = tool) -> None:
                if tool in exercised:
                    relevant = [
                        c
                        for c in checks
                        if c.name
                        in (
                            "create scratch directory",
                            "all 256 byte values",
                            "chunked file larger than max_frame",
                        )
                    ]
                    require(all(c.status == "PASS" for c in relevant), "scratch tool check failed")
                    if tool == "delete":
                        raise SkipCheck("covered by cleanup check below")
                    return
                if tool not in safe:
                    raise SkipCheck("no non-destructive probe for this tool")
                try:
                    client.call(tool, safe[tool], timeout=5)
                except AgentError as exc:
                    require(exc.code not in ("internal", "unknown_tool", "unsupported"), str(exc))

            check("tool " + tool, probe)
    finally:
        if directory is not None:

            def cleanup() -> None:
                errors = []
                for path in [*reversed(owned_files), directory]:
                    try:
                        client.call("delete", {"path": path}, timeout=5)
                    except AgentError as exc:
                        if exc.code != "not_found":
                            errors.append(f"{path}: {exc}")
                    except Exception as exc:
                        errors.append(f"{path}: {exc}")
                require(not errors, "; ".join(errors))

            check("remove scratch files and directory", cleanup)
            for index, result in enumerate(checks):
                if result.name == "tool delete":
                    checks[index] = Check(
                        result.name, checks[-1].status, "covered by scratch cleanup"
                    )
    return checks


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="HOST:PORT, [IPv6]:PORT or unix:PATH")
    parser.add_argument("--scratch", help="existing guest directory (default: hello temp)")
    parser.add_argument(
        "--second", help="second endpoint, e.g. unix:PATH for virtio-serial lane .1"
    )
    args = parser.parse_args(argv)
    try:
        with ExitStack() as stack:
            transport = stack.enter_context(transport_for(args.endpoint))
            second = (
                AgentClient(stack.enter_context(transport_for(args.second)))
                if args.second
                else None
            )
            checks = run(AgentClient(transport), args.scratch, second=second)
    except (ValueError, OSError) as exc:
        checks = [Check("connection", "FAIL", str(exc))]
    print(f"{'CHECK':48} {'RESULT':6} DETAIL")
    for item in checks:
        detail = item.detail.replace("\n", " ").replace("\r", " ")
        print(f"{item.name:48} {item.status:6} {detail}")
    counts = {
        status: sum(item.status == status for item in checks) for status in ("PASS", "FAIL", "SKIP")
    }
    print("  ".join(f"{status}: {count}" for status, count in counts.items()))
    return int(counts["FAIL"] > 0)


if __name__ == "__main__":
    raise SystemExit(main())
