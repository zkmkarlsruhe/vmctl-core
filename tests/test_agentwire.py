"""VA1 client and live-conformance tests with deterministic, in-memory guests."""

from __future__ import annotations

import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from queue import Empty, Queue

import pytest

from vmctl_core.agentwire import (
    AgentClient,
    AgentError,
    ProtocolError,
    SocketTransport,
    TCPTransport,
    UnixTransport,
    _va1,
    numbered_list,
    transport_for,
)
from vmctl_core.agentwire.client import Reply, encode_arguments
from vmctl_core.agentwire.conformance import _join, image_header, main, run
from vmctl_core.agentwire.fakeagent import FakeAgent


class MemorySocket:
    """Socket-shaped byte stream, for environments that forbid even socketpair I/O."""

    def __init__(self):
        self.inbox = Queue()
        self.pending = b""
        self.timeout = None
        self.closed = False
        self.eof = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, data):
        if self.closed or self.peer.closed:
            raise BrokenPipeError("closed memory stream")
        self.peer.inbox.put(data)

    def recv(self, count):
        if not self.pending and not self.eof:
            try:
                data = self.inbox.get(timeout=self.timeout)
            except Empty as exc:
                raise TimeoutError("memory stream timeout") from exc
            if data is None:
                self.eof = True
            else:
                self.pending = data
        data, self.pending = self.pending[:count], self.pending[count:]
        return data

    def close(self):
        if not self.closed:
            self.closed = True
            self.inbox.put(None)
            self.peer.inbox.put(None)

    def shutdown(self, _how):
        self.close()


def memory_connect(agent):
    def connect(timeout):
        client, server = MemorySocket(), MemorySocket()
        client.peer, server.peer = server, client
        client.settimeout(timeout)
        agent.start(server)
        return client

    return connect


def socketpair_available():
    try:
        left, right = socket.socketpair()
        with left, right:
            left.sendall(b"x")
            assert right.recv(1) == b"x"
    except PermissionError as exc:
        pytest.skip(f"sandbox forbids socketpair I/O: {exc}")


@contextmanager
def connected(agent=None, mode="memory", *, policy="persistent", pool_size=2, **settings):
    agent = agent or FakeAgent(max_frame=1024)
    transport = None
    try:
        if mode == "socketpair":
            socketpair_available()
        transport = SocketTransport(
            memory_connect(agent) if mode == "memory" else agent.connect,
            policy=policy,
            pool_size=pool_size,
        )
        yield agent, AgentClient(transport, **settings)
    finally:
        if transport is not None:
            transport.close()
        agent.close()


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
@pytest.mark.parametrize("charset", ("utf-8", "macroman", "cp1252", "cp437"))
def test_charset_rows_numbered_arguments_and_raw(mode, charset):
    with connected(FakeAgent(charset=charset, max_frame=1024), mode) as (agent, client):
        hello = client.hello()
        assert hello.charset == charset and hello.max_frame == 1024
        assert client.hello() is hello
        path = "/tmp/café%\nfile"
        data = bytes(range(256)) * 10
        assert client.write_file(path, data) == len(data)
        assert client.read_file(path) == data
        rows = client.call("list_dir", {"path": "/tmp"}).payload
        assert rows == [{"name": "café%\nfile", "type": "f", "size": str(len(data)), "mtime": "0"}]
        reply = client.call("run_app", {"path": path, "arg": ["café", "a=b\r\n", ""]})
        assert reply.kv["pid"] == "2"
        args = next(args for _, tool, args in agent.calls if tool == "run_app")
        assert numbered_list(args) == ["café", "a=b\r\n", ""]
        assert client.call("list_processes").payload[-1] == {"pid": "2", "name": path}
        assert agent.executions["hello"] == 1
        image_header(*client.screenshot())
        with pytest.raises(AgentError) as error:
            client.call("stat", {"path": "/tmp/é-missing"})
        assert error.value.code == "not_found"
        assert error.value.msg == "/tmp/é-missing"
        assert error.value.kv["msg"] == error.value.msg


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
@pytest.mark.parametrize("fault", ("garbage", "bad_crc", "drop"))
def test_fault_recovery_preserves_id_and_executes_once(mode, fault):
    with connected(mode=mode, retry_delay=0.001) as (agent, client):
        client.hello()
        agent.inject(fault, tool="write_file")
        assert client.write_file("/tmp/file", b"abc") == 3
        attempts = [ident for ident, tool, _ in agent.calls if tool == "write_file"]
        assert len(attempts) == (1 if fault == "garbage" else 2)
        assert len(set(attempts)) == 1
        assert agent.executions["write_file"] == 1
        assert client.read_file("/tmp/file") == b"abc"
        client.call("ping")
        client.call("ping")
        ids = [ident for ident, tool, _ in agent.calls if tool == "ping"]
        assert len(set(ids)) == 2


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
def test_tool_timeout_and_ping_on_other_connection(mode):
    with connected(mode=mode, grace=0.1) as (agent, client):
        client.hello()
        agent.inject("slow", tool="run_shell", delay=0.5)
        with ThreadPoolExecutor() as executor:
            future = executor.submit(client.call, "run_shell", {"cmd": "test"}, timeout=0.2)
            until = time.monotonic() + 1
            while agent.executions["run_shell"] == 0 and time.monotonic() < until:
                time.sleep(0.001)
            assert client.call("ping", timeout=0.05).kv["load"] == ""
            assert not future.done()
            with pytest.raises(AgentError, match="timeout"):
                future.result()
        assert agent.executions["hello"] == 2


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
def test_transport_timeout_busy_then_replay(mode):
    class SlowResponse(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "write_file":
                time.sleep(0.12)
            return super()._tool(ident, tool, args, kind, payload)

    with connected(SlowResponse(max_frame=1024), mode, grace=0.01, retries=6, retry_delay=0.01) as (
        agent,
        client,
    ):
        client.hello()
        client.call(
            "write_file", {"path": "/tmp/once", "truncate": True}, b"x", "raw", timeout=0.03
        )
        attempts = [ident for ident, tool, _ in agent.calls if tool == "write_file"]
        assert len(attempts) >= 3
        assert len(set(attempts)) == 1
        assert agent.executions["write_file"] == 1


def test_retry_bound_and_hello_replay():
    class AlwaysBroken(FakeAgent):
        def serve(self, sock):
            sock.close()

    with (
        connected(AlwaysBroken(), retries=1, retry_delay=0) as (_, client),
        pytest.raises(ConnectionError),
    ):
        client.hello(timeout=0.05)
    with connected(retry_delay=0) as (agent, client):
        agent.inject("drop", tool="hello")
        client.hello()
        ids = [ident for ident, tool, _ in agent.calls if tool == "hello"]
        assert len(ids) == 2 and len(set(ids)) == 1
        assert agent.executions["hello"] == 1


@pytest.mark.parametrize("policy,hello_count", (("persistent", 1), ("per_call", 3)))
def test_connection_policy(policy, hello_count):
    with connected(policy=policy) as (agent, client):
        for _ in range(3):
            client.call("ping")
        assert agent.executions["hello"] == hello_count


def test_same_connection_serializes_callers():
    with connected(pool_size=1) as (agent, client):
        agent.inject("slow", tool="run_shell", delay=0.1)
        with ThreadPoolExecutor(max_workers=4) as executor:
            replies = list(executor.map(lambda _: client.call("run_shell", {"cmd": "x"}), range(8)))
        assert len(replies) == 8
        assert agent.executions["hello"] == 1
        assert agent.executions["run_shell"] == 8


def test_pool_wait_timeout_and_close():
    with connected(pool_size=1) as (_, client):
        with (
            client.transport.connection(),
            pytest.raises(TimeoutError, match="pool exhausted"),
            client.transport.connection(0.01),
        ):
            pass
        client.transport.close()
        with pytest.raises(RuntimeError, match="closed"):
            client.call("ping")


@pytest.mark.parametrize("b64", (False, True))
def test_chunk_limits_long_escaped_path_empty_files_and_truncate(b64):
    caps = frozenset({"b64"}) if b64 else frozenset()
    with connected(FakeAgent(max_frame=768, caps=caps)) as (agent, client):
        path = "/tmp/" + "%" * 100
        data = bytes(range(256)) * 12
        assert client.write_file(path, data) == len(data)
        assert client.read_file(path) == data
        assert agent.executions["write_file"] > 5
        assert agent.executions["read_file"] > 5
        assert client.write_file(path, b"") == 0
        assert client.read_file(path) == b""
        assert agent.files[path] == b""
        with pytest.raises(ValueError, match="max_frame"):
            client.call("write_file", {"path": path}, b"x" * 768, "raw")


def test_response_validation_and_argument_validation():
    class BadRead(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "read_file":
                return self._reply(ident, {"offset": "0", "size": "1", "eof": "0"}, "raw", b"")
            return super()._tool(ident, tool, args, kind, payload)

    with connected(BadRead(max_frame=1024)) as (_, client):
        with pytest.raises(ProtocolError, match="no progress"):
            client.read_file("/tmp/no-progress")
        for timeout in (-1, float("nan"), float("inf")):
            with pytest.raises(ValueError, match="timeout"):
                client.call("ping", timeout=timeout)
        with pytest.raises(ValueError, match="reserved"):
            client.call("ping", {"tool": "shutdown"})
        with pytest.raises(ValueError, match="duplicate"):
            encode_arguments({"arg": ["x"], "arg.0": "y"}, "utf-8")
        with pytest.raises(_va1.FrameError):
            numbered_list({"arg.1": "gap"})


def test_beat_and_wrong_reply_id():
    class Beats(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            reply = super()._tool(ident, tool, args, kind, payload)
            if tool == "ping":
                return _va1.encode_frame("0", "BEAT", {"n": b"1", "t": b"0"}, "-", b"") + reply
            return reply

    with connected(Beats(caps=frozenset({"beat"}))) as (_, client):
        assert "t" in client.call("ping").kv
    with connected(Beats(), retries=0) as (_, client), pytest.raises(_va1.FrameError):
        client.call("ping")

    class WrongID(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            return super()._tool(b"wrong" if tool == "ping" else ident, tool, args, kind, payload)

    with connected(WrongID(), retries=0) as (_, client), pytest.raises(_va1.FrameError):
        client.call("ping")


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
def test_conformance_and_non_destructive_cleanup(mode):
    with connected(mode=mode) as (agent, client):
        agent.files["/tmp/keep"] = b"unrelated"
        original_processes = agent.processes.copy()
        with SocketTransport(client.transport.connect) as second:
            checks = run(client, second=AgentClient(second))
        assert not [c for c in checks if c.status == "FAIL"], checks
        assert sum(c.status == "PASS" for c in checks) >= 20
        assert all(c.status == "PASS" for c in checks if c.name in CROSS_STREAM_CHECKS)
        assert any(c.name == "tool shutdown" and c.status == "SKIP" for c in checks)
        assert agent.files == {"/tmp/keep": b"unrelated"}
        assert agent.directories == {"/", "/tmp"}
        assert agent.processes == original_processes
        for _, tool, args in agent.calls:
            if tool in ("write_file", "make_dir", "delete"):
                assert args["path"].startswith("/tmp/va1-")
        assert agent.executions["shutdown"] == agent.executions["restart"] == 0
        assert agent.executions["mouse"] == agent.executions["kill_process"] == 0


@pytest.mark.parametrize("mode", ("memory", "socketpair"))
@pytest.mark.parametrize("fault", ("garbage", "bad_crc", "drop", "slow"))
def test_conformance_with_faults(fault, mode):
    with connected(mode=mode, retry_delay=0.001) as (agent, client):
        agent.inject(fault, tool="write_file", delay=0.01)
        checks = run(client, "/tmp")
        assert not [c for c in checks if c.status == "FAIL"], checks
        assert not agent.files


def test_conformance_reports_failure_and_still_cleans():
    class BadScreenshot(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "screenshot":
                return self._reply(
                    ident, {"format": "png", "width": "1", "height": "1"}, "raw", b"broken"
                )
            return super()._tool(ident, tool, args, kind, payload)

    with connected(BadScreenshot(max_frame=1024)) as (agent, client):
        checks = run(client)
        assert any(c.name == "screenshot image header" and c.status == "FAIL" for c in checks)
        assert checks[-1].name == "remove scratch files and directory"
        assert checks[-1].status == "PASS"
        assert not agent.files and agent.directories == {"/", "/tmp"}


@pytest.mark.parametrize("mode", ("tcp", "unix"))
def test_loopback_conformance_cli_and_policy(mode, tmp_path):
    agent = FakeAgent(charset="macroman", max_frame=1024)
    try:
        with agent.listen(str(tmp_path / "agent.sock") if mode == "unix" else None) as endpoint:
            with transport_for(endpoint, policy="per_call", pool_size=2) as transport:
                client = AgentClient(transport)
                for fault in ("garbage", "bad_crc", "drop", "slow"):
                    agent.inject(fault, tool="write_file", delay=0.01)
                    assert client.write_file("/tmp/live", b"\xff") == 1
                    assert client.read_file("/tmp/live") == b"\xff"
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "vmctl_core.agentwire.conformance",
                    endpoint,
                    "--scratch",
                    "/tmp",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            assert "FAIL: 0" in result.stdout
            assert agent.files == {"/tmp/live": b"\xff"}
    except PermissionError as exc:
        pytest.skip(f"sandbox forbids {mode} sockets: {exc}")


def test_cli_table_and_nonzero_failure(monkeypatch, capsys):
    agent = FakeAgent(max_frame=1024)

    @contextmanager
    def transport(*args, **kwargs):
        with SocketTransport(memory_connect(agent), pool_size=2) as result:
            yield result

    monkeypatch.setattr("vmctl_core.agentwire.conformance.transport_for", transport)
    try:
        assert main(["unused:1", "--scratch", "/tmp"]) == 0
        output = capsys.readouterr().out
        assert "RESULT" in output and "FAIL: 0" in output
        agent.tools = agent.tools - {"ping"}
        assert main(["unused:1"]) == 1
        assert "FAIL" in capsys.readouterr().out
    finally:
        agent.close()


def test_rows_request_and_hello_fields_validation():
    class Echo(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "run_script":
                return self._reply(ident, {"arg.0": "é", "arg.1": "x"}, kind.decode(), payload)
            return super()._tool(ident, tool, args, kind, payload)

    with connected(Echo(charset="macroman")) as (_, client):
        rows = [{"name": "é", "value": "a\tb%\r\n"}]
        reply = client.call("run_script", payload=rows, kind="rows")
        assert reply.payload == rows
        assert reply.numbered() == ["é", "x"]

    class BadHello(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            return _va1.encode_frame(ident, "OK", {"cs": b"utf-8"}, "-", b"")

    with connected(BadHello()) as (_, client), pytest.raises(ProtocolError, match="hello"):
        client.hello()


def test_oversized_frame_then_good_frame():
    with connected() as (_, client), client.transport.connection() as conn:
        hello = client._hello(conn)
        huge = _va1.encode_frame(
            "large", "CALL", {"tool": b"write_file"}, "raw", b"x" * hello.max_frame
        )
        good = _va1.encode_frame("good", "CALL", {"tool": b"ping"}, "-", b"")
        conn.send(huge + good)
        assert dict(conn.receive(b"large")[2])[b"code"] == b"too_large"
        assert conn.receive(b"good")[1] == b"OK"


def test_image_header_rejects_dimension_mismatch():
    with connected() as (_, client):
        format, width, height, data = client.screenshot()
        with pytest.raises(ValueError, match="dimensions"):
            image_header(format, width + 1, height, data)
        corrupt = data[:29] + bytes(value ^ 1 for value in data[29:33]) + data[33:]
        with pytest.raises(ValueError, match="checksum"):
            image_header(format, width, height, corrupt)
        image_header("ppm", 2, 1, b"P6\n# comment\n2 1\n255\n" + bytes(6))


def test_transport_endpoint_rejects_http():
    with pytest.raises(ValueError):
        transport_for("http://localhost:9009")
    with pytest.raises(ValueError):
        transport_for("unix:")


def test_hello_timeout_busy_and_replay():
    with connected(grace=0.01, retries=5, retry_delay=0.005) as (agent, client):
        agent.inject("slow", tool="hello", delay=0.08)
        assert client.hello(timeout=0.02).charset == "utf-8"
        ids = [ident for ident, tool, _ in agent.calls if tool == "hello"]
        assert len(ids) >= 3 and len(set(ids)) == 1
        assert agent.executions["hello"] == 1


def test_busy_retry_deadline_is_bounded():
    class Busy(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "ping":
                return _va1.error_frame(ident, "busy", b"still running")
            return super()._tool(ident, tool, args, kind, payload)

    with connected(Busy(), grace=0.01, retries=1, retry_delay=0.005) as (_, client):
        start = time.monotonic()
        with pytest.raises((TimeoutError, AgentError)):
            client.call("ping", timeout=0.02)
        assert time.monotonic() - start < 0.5


def test_reconnect_negotiates_charset_and_frame_limit_again():
    first = FakeAgent(charset="utf-8", max_frame=1024)
    second = FakeAgent(charset="macroman", max_frame=768)
    connections = iter([memory_connect(first), memory_connect(second)])
    try:
        with SocketTransport(
            lambda timeout: next(connections)(timeout), policy="per_call"
        ) as transport:
            client = AgentClient(transport)
            assert client.call("run_shell", {"cmd": "é"}).kv["stdout"] == "é"
            assert client.call("run_shell", {"cmd": "é"}).kv["stdout"] == "é"
        assert first.executions["hello"] == second.executions["hello"] == 1
    finally:
        first.close()
        second.close()


def test_remote_crc_error_retries_original_id():
    class RequestCRC(FakeAgent):
        def serve(self, sock):
            reader = _va1.FrameReader(sock.recv, 4096)
            hello = reader.next()
            sock.sendall(self._tool(hello[0], "hello", {}, b"-", b""))
            call = reader.next()
            self.calls.append((call[0], "ping", {}))
            if len(self.calls) == 1:
                sock.sendall(_va1.error_frame(call[0], "crc", b"corrupt request"))
            else:
                sock.sendall(self._tool(call[0], "ping", {}, b"-", b""))
            sock.close()

    with connected(RequestCRC(), retry_delay=0) as (agent, client):
        assert "t" in client.call("ping").kv
        assert len(agent.calls) == 2
        assert agent.calls[0][0] == agent.calls[1][0]


CROSS_STREAM_CHECKS = {
    "stored reply replay across streams",
    "busy and ping during running call",
}


@pytest.mark.parametrize("second_lane", (False, True))
def test_unix_conformance_uses_one_connection_per_lane(second_lane, monkeypatch, capsys):
    agent = FakeAgent(max_frame=1024)
    ports = {}

    def transport(endpoint):
        assert endpoint not in ports
        result = UnixTransport(endpoint.removeprefix("unix:"))
        opened = []

        def connect(timeout):
            # A serial port cannot accept another connection while its first is open.
            assert not any(not sock.closed for sock in opened), "second connection to one port"
            sock = memory_connect(agent)(timeout)
            opened.append(sock)
            return sock

        result.connect = connect
        ports[endpoint] = opened
        return result

    monkeypatch.setattr("vmctl_core.agentwire.conformance.transport_for", transport)
    args = ["unix:/lane.0"] + (["--second", "unix:/lane.1"] if second_lane else [])
    try:
        assert main(args) == 0
        output = capsys.readouterr().out
        assert "FAIL: 0" in output
        for name in CROSS_STREAM_CHECKS:
            line = next(line for line in output.splitlines() if line.startswith(name))
            assert ("PASS" if second_lane else "SKIP") in line
            if not second_lane:
                assert "--second unix:PATH" in line and "only one stream" in line
        assert len(ports) == (2 if second_lane else 1)
        assert all(len(opened) == 1 for opened in ports.values())
        assert not agent.files and agent.directories == {"/", "/tmp"}
    finally:
        agent.close()


def test_unix_second_endpoint_cannot_reopen_same_path():
    agent = FakeAgent(max_frame=1024)
    try:
        with UnixTransport("/lane.0") as primary, UnixTransport("/./lane.0") as second:
            primary.connect = memory_connect(agent)
            second.connect = lambda timeout: pytest.fail("same Unix port reopened")
            checks = run(AgentClient(primary), second=AgentClient(second))
            failures = [c for c in checks if c.status == "FAIL"]
            assert {c.name for c in failures} == CROSS_STREAM_CHECKS
            assert all("different socket path" in c.detail for c in failures)
    finally:
        agent.close()


def test_tcp_conformance_opens_other_streams_without_second():
    agent = FakeAgent(max_frame=1024)
    try:
        with TCPTransport("unused") as transport:
            transport.connect = memory_connect(agent)
            checks = run(AgentClient(transport))
            assert not [c for c in checks if c.status == "FAIL"], checks
            assert all(c.status == "PASS" for c in checks if c.name in CROSS_STREAM_CHECKS)
            # Primary negotiation, two observer streams, and the advertised-tool probe.
            assert agent.executions["hello"] == 4
    finally:
        agent.close()


@pytest.mark.parametrize(
    ("native_temp", "os_name", "charset", "separator"),
    [("C:\\Temp\\é", "windows", "cp1252", "\\"), ("Disk:Temp:é:", "macos", "macroman", ":")],
)
def test_conformance_uses_native_hello_temp(native_temp, os_name, charset, separator):
    class NativePaths(FakeAgent):
        def _reply(self, ident, kv, kind="-", payload=b""):
            if "temp" in kv:
                kv = dict(kv, temp=native_temp, os=os_name)
            return super()._reply(ident, kv, kind, payload)

        def _tool(self, ident, tool, args, kind, payload):
            if "path" in args:
                assert args["path"].startswith(native_temp.rstrip(separator) + separator)
                suffix = args["path"][len(native_temp.rstrip(separator)) :]
                args = dict(args, path="/tmp" + suffix.replace(separator, "/"))
            return super()._tool(ident, tool, args, kind, payload)

    with connected(NativePaths(charset=charset, max_frame=1024)) as (agent, client):
        checks = run(client)
        assert not [c for c in checks if c.status == "FAIL"], checks
        assert next(c for c in checks if c.name == "create scratch directory").status == "PASS"
        assert not agent.files and agent.directories == {"/", "/tmp"}


@pytest.mark.parametrize("override", (None, "/override"))
def test_scratch_defaults_to_hello_temp(override):
    agent = FakeAgent(temp="/scratch-é", max_frame=1024)
    agent.directories.add("/override")
    with connected(agent) as (_, client):
        checks = run(client, override)
        assert not [c for c in checks if c.status == "FAIL"], checks
        parent = override or agent.temp
        paths = [args["path"] for _, tool, args in agent.calls if tool == "make_dir"]
        assert len(paths) == 1 and paths[0].startswith(parent + "/va1-")
        assert agent.directories == {"/", agent.temp, "/override"} and not agent.files


@pytest.mark.parametrize(
    ("parent", "expected"),
    [("C:\\Temp", "C:\\Temp\\child"), ("Disk:Temp:", "Disk:Temp:child"), ("/tmp", "/tmp/child")],
)
def test_native_scratch_child(parent, expected):
    assert _join(parent, "child") == expected


@pytest.mark.parametrize("temp", (None, ""))
def test_hello_requires_temp(temp):
    from vmctl_core.agentwire.client import parse_hello

    with connected() as (_, client):
        kv = client.hello().kv.copy()
    if temp is None:
        kv.pop("temp")
    else:
        kv["temp"] = temp
    with pytest.raises(ProtocolError, match="hello"):
        parse_hello(
            (
                b"h",
                b"OK",
                [
                    (key.encode("ascii"), value)
                    for key, value in encode_arguments(kv, "utf-8").items()
                ],
                b"-",
                b"",
            )
        )


@pytest.mark.parametrize("caps", (frozenset(), frozenset({"b64"})))
@pytest.mark.parametrize("policy", ("persistent", "per_call"))
def test_screenshot_paging_and_retained_capture(caps, policy):
    with connected(FakeAgent(max_frame=1024, caps=caps), policy=policy) as (agent, client):
        assert client.hello().kv["protocol"] == "1.1"
        assert client.screenshot("bmp") == agent.screenshot
        image_header(*agent.screenshot)
        calls = [args for _, tool, args in agent.calls if tool == "screenshot"]
        assert len(calls) > 1
        assert "capture" not in calls[0]
        assert len({args["capture"] for args in calls[1:]}) == 1
        length = 384 if caps else 512
        assert [int(args["offset"]) for args in calls] == list(
            range(0, len(agent.screenshot[3]), length)
        )
        assert all(int(args["length"]) == length for args in calls)
        old_capture = calls[1]["capture"]
        first = client.call("screenshot", {"length": 1})
        assert first.kv["capture"] != old_capture
        with pytest.raises(AgentError, match="not_found"):
            client.call("screenshot", {"capture": old_capture, "offset": 1, "length": 1})
        # Changing the next capture's source must not change a retained image.
        agent.screenshot = ("png", 1, 1, b"replacement")
        page = client.call("screenshot", {"capture": first.kv["capture"], "offset": 1, "length": 4})
        assert page.payload == b"PNG\r"


@pytest.mark.parametrize(
    ("page", "key", "value"),
    [
        (1, "capture", ""),
        (1, "format", ""),
        (1, "width", "0"),
        (1, "height", "-1"),
        (1, "size", "-1"),
        (1, "size", "1"),
        (1, "size", "bad"),
        (1, "capture", None),
        (1, "offset", None),
        (1, "eof", None),
        (2, "capture", "changed"),
        (2, "format", "bmp"),
        (2, "width", "33"),
        (2, "height", "33"),
        (2, "size", "9999"),
        (2, "offset", "0"),
        (2, "eof", "2"),
        (1, "eof", "1"),
        (2, "eof", "0"),
        (1, "payload", b""),
        (1, "payload", b"x" * 513),
        (1, "kind", "-"),
    ],
)
def test_screenshot_rejects_malformed_pages(page, key, value, monkeypatch):
    with connected() as (agent, client):
        agent.screenshot = ("png", 32, 32, b"x" * 513)
        original = client.call
        pages = 0

        def call(tool, *args, **kwargs):
            nonlocal pages
            reply = original(tool, *args, **kwargs)
            pages += 1
            if pages == page:
                if key == "payload":
                    return Reply(reply.kv, reply.kind, value)
                if key == "kind":
                    return Reply(reply.kv, value, reply.payload)
                if value is None:
                    del reply.kv[key]
                else:
                    reply.kv[key] = value
            return reply

        monkeypatch.setattr(client, "call", call)
        with pytest.raises(ProtocolError, match="screenshot"):
            client.screenshot()


def test_screenshot_retry_replays_first_page_without_recapture():
    with connected(retry_delay=0) as (agent, client):
        agent.inject("drop", tool="screenshot")
        assert client.screenshot() == agent.screenshot
        starts = [
            (ident, args)
            for ident, tool, args in agent.calls
            if tool == "screenshot" and "capture" not in args
        ]
        assert len(starts) == 2 and starts[0] == starts[1]
        assert agent.executions["screenshot"] == 7


@pytest.mark.parametrize("prefix", (b"", bytes(512)))
@pytest.mark.parametrize("version", (1, 2))
def test_pict_headers(prefix, version):
    data = struct.pack(">Hhhhh", 0, -5, -10, 15, 30)
    data += (
        b"\x11\x01\xff" if version == 1 else b"\x00\x11\x02\xff\x0c\x00" + bytes(24) + b"\x00\xff"
    )
    image_header("pict", 40, 20, prefix + data)
    with pytest.raises(ValueError, match="dimensions"):
        image_header("pict", 41, 20, prefix + data)
    with pytest.raises(ValueError, match="PICT"):
        image_header("pict", 40, 20, prefix + data[:11])


def test_bmp_headers():
    header = b"BM" + bytes(12) + struct.pack("<Iii", 40, 2, -3) + bytes(28)
    image_header("bmp", 2, 3, header)
    with pytest.raises(ValueError, match="dimensions"):
        image_header("bmp", 3, 2, header)
    with pytest.raises(ValueError, match="BMP"):
        image_header("bmp", 2, 3, header[:25])


def test_fake_unix_listener_rejects_second_stream(tmp_path):
    agent = FakeAgent()
    try:
        with (
            agent.listen(str(tmp_path / "single.sock")) as endpoint,
            transport_for(endpoint) as first,
            transport_for(endpoint) as second,
        ):
            AgentClient(first).hello()
            with pytest.raises((OSError, _va1.FrameError)):
                AgentClient(second, retries=0).hello(timeout=0.2)
            assert "t" in AgentClient(first).call("ping").kv
    except PermissionError as exc:
        pytest.skip(f"sandbox forbids Unix sockets: {exc}")
    finally:
        agent.close()


@pytest.mark.parametrize("format", ("png", "bmp", "pict"))
def test_screenshot_validates_reassembled_image(format):
    with connected() as (agent, client):
        if format == "bmp":
            data = b"BM" + bytes(12) + struct.pack("<Iii", 40, 32, 32) + bytes(3100)
            agent.screenshot = (format, 32, 32, data)
        elif format == "pict":
            data = bytes(512) + struct.pack(">Hhhhh", 0, 0, 0, 32, 32) + b"\x11\x01" + bytes(600)
            agent.screenshot = (format, 32, 32, data)
        assert client.screenshot() == agent.screenshot
        assert agent.executions["screenshot"] > 1
        agent.screenshot = (format, 32, 32, b"x" * 1200)
        with pytest.raises(ProtocolError, match="header"):
            client.screenshot()
        checks = run(client)
        assert any(c.name == "screenshot image header" and c.status == "FAIL" for c in checks)
        assert not agent.files and agent.directories == {"/", "/tmp"}


def test_unknown_screenshot_format_is_not_certified():
    with connected() as (agent, client):
        agent.screenshot = ("unknown", 1, 1, b"opaque image")
        assert client.screenshot() == agent.screenshot
        checks = run(client)
        header = next(c for c in checks if c.name == "screenshot image header")
        assert header.status == "SKIP" and "unavailable for unknown" in header.detail
