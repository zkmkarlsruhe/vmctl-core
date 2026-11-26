"""Backend VA1 integration over real Unix/TCP sockets; no emulator or guest required."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, contextmanager
from copy import copy
from pathlib import Path
from threading import Event

import pytest
from test_agentwire import memory_connect, socketpair_available

from vmctl_core.agentwire import Reply, SocketTransport, TCPTransport, UnixTransport
from vmctl_core.agentwire.fakeagent import FakeAgent
from vmctl_core.backends import (
    AgentUnreachable,
    BackendError,
    BasiliskIIBackend,
    MacEmuSettings,
    Q800Backend,
)
from vmctl_core.backends._agent import agent_session
from vmctl_core.guestos.modules.mac_os_9 import MacOS9Module


@pytest.fixture(params=["memory", "sockets"])
def listen_agent(request, monkeypatch):
    """Exercise the same backend paths with memory streams and real socket listeners."""
    listeners = {}
    if request.param == "memory":

        def unix_init(self, path):
            def connect(timeout):
                if path not in listeners or not Path(path).exists():
                    raise ConnectionRefusedError(path)
                return memory_connect(listeners[path])(timeout)

            SocketTransport.__init__(self, connect)

        def tcp_init(self, host, port=9009):
            def connect(timeout):
                endpoint = f"{host}:{port}"
                if endpoint not in listeners:
                    raise ConnectionRefusedError(endpoint)
                return memory_connect(listeners[endpoint])(timeout)

            SocketTransport.__init__(self, connect)

        monkeypatch.setattr(UnixTransport, "__init__", unix_init)
        monkeypatch.setattr(TCPTransport, "__init__", tcp_init)

    @contextmanager
    def listen(agent, path=None):
        if request.param == "sockets":
            with ExitStack() as stack:
                try:
                    endpoint = stack.enter_context(agent.listen(path))
                except PermissionError as exc:
                    pytest.skip(f"sandbox forbids socket listeners: {exc}")
                yield endpoint
        else:
            endpoint = path or "127.0.0.1:9009"
            listeners[endpoint] = agent
            if path:
                Path(path).touch()
            try:
                yield "unix:" + path if path else endpoint
            finally:
                listeners.pop(endpoint)
                agent.close()
                if path:
                    Path(path).unlink(missing_ok=True)

    return listen


@pytest.fixture(params=["memory", "socketpair"])
def agent_connect(request):
    if request.param == "socketpair":
        socketpair_available()
        return lambda agent: agent.connect
    return memory_connect


@pytest.fixture(params=["q800-network", "q800-serial", "q800-tap", "mac-serial", "mac-network"])
def backend_agent(request, tmp_path, monkeypatch, listen_agent):
    settings = MacEmuSettings(state_dir=tmp_path)
    agent = FakeAgent(charset="macroman", max_frame=1024, temp="/scratch-é")
    with ExitStack() as stack:
        if request.param.startswith("q800"):
            be = Q800Backend("v", instance_dir=tmp_path / "v", settings=settings)
            be.instance_dir.mkdir()
            monkeypatch.setattr(be, "is_running", lambda: True)
            net = {"mode": "slirp"}
            monkeypatch.setattr(be, "spec", lambda: {"net": net})
            if request.param == "q800-tap":
                endpoint = stack.enter_context(listen_agent(agent))
                host, port = endpoint.split(":")
                net.update(mode="tap", ip=host)
                monkeypatch.setattr("vmctl_core.backends.qemu_q800.AGENT_PORT", int(port))
                assert be.agent_endpoint() == (host, int(port))
            else:
                path = be.agent_sock_path
                if request.param == "q800-serial":
                    path = be.serial_path("b")
                    be._mark_agent_seen()
                stack.enter_context(listen_agent(agent, str(path)))
        else:
            lane = "serial" if request.param == "mac-serial" else "http"
            port = 0
            if lane == "http":
                endpoint = stack.enter_context(listen_agent(agent))
                port = int(endpoint.split(":")[1])
            be = BasiliskIIBackend(
                "v", settings=settings, disk="d.img", agent=lane, agent_port=port
            )
            be.instance_dir.mkdir(parents=True)
            if lane == "serial":
                stack.enter_context(listen_agent(agent, str(be.agent_sock_path)))
        yield be, agent


def call(be, tool, **args):
    if isinstance(be, Q800Backend):
        return be.agent_call(tool, args)
    return be._agent_call(tool, **args)


def test_va1_ping_rows_raw_and_errors(backend_agent):
    be, agent = backend_agent
    assert be.guest_ping()
    reply = call(be, "list_processes")
    assert isinstance(reply, Reply)
    assert reply.kind == "rows" and reply.payload == [{"pid": "1", "name": "init"}]
    reply = call(be, "screenshot", length=32)
    assert reply.kind == "raw" and reply.payload.startswith(b"\x89PNG\r\n\x1a\n")
    assert len(reply.payload) == 32 and reply.kv["eof"] == "0"
    assert int(reply.kv["size"]) == len(agent.screenshot[3])
    with pytest.raises(BackendError, match="unknown_tool"):
        call(be, "not_a_tool")
    with pytest.raises(BackendError, match="unsupported"):
        call(be, "win.reg_write")
    with pytest.raises(BackendError, match="exceeds max_frame"):
        call(be, "send_keys", keys="x" * 2000)
    assert agent.calls[0][1] == "hello"


def test_va1_binary_file_chunks_and_empty_truncation(backend_agent):
    be, agent = backend_agent
    with be._agent_session() as client:
        hello = client.hello()
        assert hello.kv["protocol"] == "1.1"
        assert hello.kv["temp"] == agent.temp
        path = hello.kv["temp"] + "/café"
    data = bytes(range(256)) * 80
    be.guest_write_file(path, data)
    assert be.guest_read_file(path) == data
    assert agent.executions["write_file"] > 1
    assert agent.executions["read_file"] > 1
    writes = [args for _, tool, args in agent.calls if tool == "write_file"]
    assert writes[0]["truncate"] == "1" and writes[0]["offset"] == "0"
    assert all(args["truncate"] == "0" for args in writes[1:])
    be.guest_write_file(path, b"")
    assert be.guest_read_file(path) == b""
    assert agent.files[path] == b""


@pytest.mark.parametrize("fault", ["garbage", "bad_crc", "drop"])
def test_va1_retries_keep_mutations_single_execution(backend_agent, fault):
    be, agent = backend_agent
    agent.inject(fault, tool="make_dir")
    call(be, "make_dir", path=agent.temp + "/new")
    assert agent.executions["make_dir"] == 1
    ids = [ident for ident, tool, _ in agent.calls if tool == "make_dir"]
    assert len(set(ids)) == 1


def test_mac_launch_adapts_reply_to_public_tuple(backend_agent):
    be, agent = backend_agent
    if isinstance(be, Q800Backend):
        with pytest.raises(BackendError, match="no shell"):
            be.guest_exec("/tmp/app")
    else:
        path = agent.temp + "/app"
        agent.files[path] = b"app"
        assert be.guest_exec(path) == (0, path, "")
        with pytest.raises(BackendError, match="no arguments"):
            be.guest_exec("/tmp/app", ["arg"])


def q800(tmp_path, monkeypatch):
    be = Q800Backend("v", instance_dir=tmp_path / "v", settings=MacEmuSettings(state_dir=tmp_path))
    be.instance_dir.mkdir()
    monkeypatch.setattr(be, "is_running", lambda: True)
    monkeypatch.setattr(be, "spec", lambda: {"net": {"mode": "slirp"}})
    return be


def test_q800_network_drop_replays_on_b_with_same_id(tmp_path, monkeypatch, listen_agent):
    be = q800(tmp_path, monkeypatch)
    agent = FakeAgent()
    agent.inject("drop", tool="make_dir")
    with (
        listen_agent(agent, str(be.agent_sock_path)),
        listen_agent(agent, str(be.serial_path("b"))),
    ):
        be.agent_call("make_dir", {"path": "/tmp/new"})
        ids = [ident for ident, tool, _ in agent.calls if tool == "make_dir"]
        assert len(ids) == 2 and ids[0] == ids[1]
        assert agent.executions["make_dir"] == 1
        assert be.agent_seen_path.exists()
        # Only serial remains; the network-only selector must fail.
        be.agent_sock_path.unlink()
        assert not be.guest_ping(lanes=("http",))
        assert be.guest_ping(lanes=("serial",))


def test_q800_post_gate_waits_for_network_without_serial_writes(
    tmp_path, monkeypatch, listen_agent
):
    be = q800(tmp_path, monkeypatch)
    agent = FakeAgent()
    with listen_agent(agent, str(be.serial_path("b"))):
        with pytest.raises(AgentUnreachable, match="serial lane closed") as exc:
            be.agent_call("ping", lanes=("serial",))
        assert not exc.value.reached_guest and not agent.calls
        assert not be.wait_serial_hello(timeout=0.1)
        assert not agent.calls
        with listen_agent(agent, str(be.agent_sock_path)):
            assert be.wait_serial_hello(timeout=1)
        assert be.guest_ping(lanes=("serial",))
        be.agent_seen_path.unlink()
        assert not be.guest_ping(lanes=("serial",))


def test_q800_no_serial_a_fallback(tmp_path, monkeypatch, listen_agent):
    be = q800(tmp_path, monkeypatch)
    be._mark_agent_seen()
    agent = FakeAgent()
    with listen_agent(agent, str(be.serial_path("a"))):
        with pytest.raises(AgentUnreachable) as exc:
            be.agent_call("ping", lanes=("serial",))
        assert not exc.value.reached_guest and not agent.calls


def test_transport_failure_after_connect_is_ambiguous(agent_connect):
    agent = FakeAgent()

    # Close every connected socket before negotiation can complete.
    def connect(timeout):
        sock = agent_connect(agent)(timeout)
        sock.shutdown(2)
        return sock

    try:
        with pytest.raises(AgentUnreachable) as exc, agent_session([connect]) as client:
            client.call("ping")
        assert exc.value.reached_guest
    finally:
        agent.close()


def test_shared_session_socketpair_and_invalid_read_metadata(agent_connect):
    class InvalidReadAgent(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "read_file":
                return self._reply(ident, {"size": "4", "offset": "1", "eof": "1"}, "raw", b"data")
            return super()._tool(ident, tool, args, kind, payload)

    agent = InvalidReadAgent()
    try:
        with (
            pytest.raises(BackendError, match="offset"),
            agent_session([agent_connect(agent)]) as client,
        ):
            assert client.call("ping").kv["uptime"]
            client.read_file("/tmp/x")
    finally:
        agent.close()


def test_mac9_reads_raw_logs_and_va1_diagnostics(agent_connect):
    agent = FakeAgent(charset="macroman", max_frame=1024)
    from vmctl_core.agentwire import AgentClient
    from vmctl_core.guestos.modules.mac_os_9 import _BREADCRUMB

    agent.files["/tmp/log"] = ("old\r" * 500 + "UP café prev=DIRTY\r").encode("macroman")
    with SocketTransport(agent_connect(agent)) as transport:
        client = AgentClient(transport)

        class Context:
            @staticmethod
            def guest_read_file(path):
                assert path == _BREADCRUMB
                return client.read_file("/tmp/log")

            @staticmethod
            def guest_call(tool, *, timeout=30.0, **args):
                return client.call(tool, args, timeout=timeout)

        try:
            records = MacOS9Module().read_logs(Context(), kind="breadcrumb", count=1)
            assert records[0].message == "UP café prev=DIRTY"
            assert records[0].level == "warning"
            assert agent.executions["read_file"] > 1
            # A larger negotiated frame accommodates the diagnostic Python script.
            agent.max_frame = 4096
            with SocketTransport(agent_connect(agent)) as other:
                client = AgentClient(other)
                records = MacOS9Module().read_logs(Context(), kind="diagnostics")
                assert records and records[0].level != "warning"
            args = next(args for _, tool, args in agent.calls if tool == "run_script")
            assert args["lang"] == "python"
        finally:
            agent.close()


def test_q800_shutdown_and_restart_use_va1_replies(tmp_path, monkeypatch, listen_agent):
    be = q800(tmp_path, monkeypatch)

    class FrontAgent(FakeAgent):
        def _tool(self, ident, tool, args, kind, payload):
            if tool == "list_processes":
                return self._rows(ident, ["pid", "name", "front"], [["1", "SimpleText", "1"]])
            return super()._tool(ident, tool, args, kind, payload)

    agent = FrontAgent()
    keys = []
    waits = iter([False, False, True])
    monkeypatch.setattr(be, "_wait_exit", lambda timeout: next(waits))
    monkeypatch.setattr(be, "_stop", lambda: None)
    monkeypatch.setattr(be, "send_key", keys.append)
    monkeypatch.setattr("vmctl_core.backends.qemu_q800.time.sleep", lambda seconds: None)
    with listen_agent(agent, str(be.agent_sock_path)):
        assert be.shutdown_clean(step_timeout=0) == "power-key"
        sent = [(tool, args) for _, tool, args in agent.calls if tool in ("send_keys", "shutdown")]
        assert sent == [
            ("shutdown", {"timeout": "10"}),
            ("send_keys", {"keys": "{cmd}q", "timeout": "10"}),
            ("shutdown", {"timeout": "10"}),
        ]
        assert keys == [["KEY_POWER"], ["KEY_ENTER"]]
        monkeypatch.setattr(be, "reset", lambda: pytest.fail("successful restart must not reset"))
        be.reboot()
        assert agent.executions["restart"] == 1


def test_backend_session_pages_one_screenshot(backend_agent):
    be, agent = backend_agent
    with be._agent_session() as client:
        assert client.screenshot() == agent.screenshot
    pages = [args for _, tool, args in agent.calls if tool == "screenshot"]
    assert len(pages) > 1
    assert "capture" not in pages[0]
    assert len({page["capture"] for page in pages[1:]}) == 1
    assert [int(page["offset"]) for page in pages] == list(
        range(0, len(agent.screenshot[3]), agent.max_frame - 512)
    )
    assert agent.executions["hello"] == 1


@pytest.mark.parametrize("backend_kind", ["q800", "mac"])
def test_serial_sessions_are_exclusive_across_backend_objects(
    tmp_path, monkeypatch, listen_agent, backend_kind
):
    if backend_kind == "q800":
        be = q800(tmp_path, monkeypatch)
        be._mark_agent_seen()
        path = be.serial_path("b")
    else:
        be = BasiliskIIBackend(
            "v", settings=MacEmuSettings(state_dir=tmp_path), disk="d.img", agent="serial"
        )
        be.instance_dir.mkdir(parents=True)
        path = be.agent_sock_path
    other = copy(be)
    agent = FakeAgent()
    holding, release, second_started = Event(), Event(), Event()

    def first():
        with be._agent_session() as client:
            client.hello()
            holding.set()
            assert release.wait(5)
            return client.call("ping")

    def second():
        second_started.set()
        with other._agent_session() as client:
            return client.call("ping")

    with listen_agent(agent, str(path)), ThreadPoolExecutor(max_workers=2) as pool:
        pending = pool.submit(first)
        try:
            assert holding.wait(5)
            following = pool.submit(second)
            assert second_started.wait(5)
            with pytest.raises(TimeoutError):
                following.result(timeout=0.1)
            assert agent.executions["hello"] == 1
        finally:
            release.set()
        assert pending.result(timeout=5).kv["uptime"]
        assert following.result(timeout=5).kv["uptime"]
        assert agent.executions["hello"] == 2
