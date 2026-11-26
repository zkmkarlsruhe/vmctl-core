# VA1 host adapter

`vmctl_core.agentwire` implements CONTRACT.md 1.1 from vmctl-guest-agent commit
`b1c1abd`. It uses only the Python standard library. The codec is unchanged from
the original pin, `c6db1f46e002f09e670da11e4a363e77d519326f`; the 1.1 branch was
compared byte-for-byte, so the vendored source and vector manifest remain unchanged.
The codec is copied after a one-line provenance header. A `.pyi` supplies
host-side types; ruff excludes the original Python 2.3-compatible source.

```python
from vmctl_core.agentwire import AgentClient, TCPTransport

with TCPTransport("127.0.0.1", 9009, pool_size=2) as transport:
    client = AgentClient(transport)
    hello = client.hello()  # charset, max_frame, tools, caps, original kv
    reply = client.call("list_dir", {"path": "/tmp"})
    rows = reply.payload  # list[dict[str, str]]
    client.write_file("/tmp/example", bytes(range(256)))
    data = client.read_file("/tmp/example")
```

`UnixTransport(path)` accepts libvirt virtio-serial channel sockets and QEMU serial
chardev sockets. `transport_for("host:9009")`, `transport_for("[::1]:9009")`, and
`transport_for("unix:/path/to/socket")` parse endpoints. There is no HTTP transport.
Keep a single connection for channel sockets that admit only one client; use a
separate channel/client for each concurrent caller on such guests.

Transports default to a persistent connection and pool size 1. `pool_size=N`
bounds concurrency and serializes each stream. `policy="per_call"` negotiates hello
and performs one call on a fresh socket, then closes it. Close transports after use;
closing a pool closes idle streams immediately and leased streams on return.
`SocketTransport(factory)` also accepts a socket factory for custom connections.
The factory takes a timeout in seconds and returns an owned connected socket.

`call(tool, args, payload=None, kind="-", timeout=30)` returns `Reply(kv, kind,
payload)`. Text arguments and reply values are Python strings, encoded in the
charset negotiated on that particular connection. Numbers and booleans become
wire text. A sequence argument expands to numbered keys, for example
`{"arg": ["first", "second"]}`. `reply.numbered("arg")` decodes numbered results
and rejects gaps. `tool` and `timeout` are reserved argument names; pass timeout
through the keyword argument. `rows` payloads become lists of dictionaries;
`raw` payloads remain bytes. The `b64` capability encodes/decodes raw data at the
wire boundary, including chunk-size accounting.

Tool failures raise `AgentError`, exposing `code`, `msg`, and the complete `kv`.
Malformed tool results raise `ProtocolError`; unrecoverable framing and socket
failures raise the codec error or `OSError`/`TimeoutError`. Text conversion is
strict: unrepresentable paths and invalid guest text are errors, not substitutions.

Each new call receives a random 16-character ID. Transport failures, CRC failures
and timeouts retry with that ID, even after reconnecting. `busy` waits for completion
and retries the same ID. Defaults are three transport retries, a 50 ms retry delay,
and the contract's 15-second response grace. Each attempt waits for the tool timeout
plus that grace; the complete retry budget is bounded by that interval multiplied
by the number of attempts. Hello negotiation is cached per connection. A reconnect
negotiates again before retrying the original operation.

`read_file` and `write_file` split transfers within negotiated `max_frame`, including
escaped path overhead and base64 expansion. Writes truncate on the first chunk,
including empty files. Both accept `fork="data"` and a per-call timeout. They reject
inconsistent offsets, changed sizes, short writes and reads that make no progress.
A failed multi-chunk write may leave a partial guest file; there is no atomic-upload
primitive in VA1. `screenshot()` returns `(format, width, height, bytes)` using the
format returned by the guest, which can differ from the requested PNG. It reassembles
pages from one retained capture within `max_frame` (including base64 expansion),
checks capture identity, dimensions, size, offset and EOF on every page, and validates
the complete image header for known formats, including PNG, BMP and PICT. Unknown
formats are returned unchanged; conformance reports their header check as SKIP.
A concurrent new screenshot replaces the guest's retained capture; paging the old
capture then raises `AgentError` with `code="not_found"`.

## Backend integration

Q800, Basilisk II and SheepShaver use one VA1 session adapter. The network lane
forwards guest TCP 9009 through the existing SLiRP Unix socket or host port; Q800
also supports direct TCP on tap networks. Q800 serial uses only ESCC channel B.
Mac emulator serial continues to use its configured PTY-to-Unix-socket bridge.
The existing `http` lane/configuration label now selects VA1 TCP, without HTTP.
Q800 also accepts `tcp` for that lane. No old JSON wire is supported.

Public parameters and defaults remain unchanged. Return annotations change only for:

- `Q800Backend.agent_call(...) -> Reply`, formerly `dict`.
- `GuestContext.guest_call(...) -> Reply`, formerly `dict`.

Callers read `reply.kv` for decoded string fields and `reply.payload` for rows or
raw bytes. Tool errors raise `BackendError` instead of returning an error envelope.
`AgentUnreachable.reached_guest` is false only if no socket connected; true means
the operation may have run. Automatic retries preserve the VA1 ID across lanes.
The retained `idempotent` argument no longer changes retry behaviour.

`guest_ping` still returns bool, `guest_read_file` bytes, and `guest_write_file`
None. File transfers use negotiated chunk sizes and validate offsets, sizes and
EOF. Mac emulator `guest_exec` returns `(0, path, "")` after a successful `run_app`
Reply; Q800 still rejects shell execution. Q800 shutdown uses VA1 shutdown and
Command-Q, then the QMP power key and hard stop; VA1 has no force-shutdown argument.
Libvirt's `guest_*` implementations use QGA exclusively and remain unchanged.

The Q800 ROM POST gate remains mandatory: sending serial bytes during POST can
hang boot. VA1 defines no unsolicited serial hello, so `wait_serial_hello()` now
waits for network readiness without touching serial. A serial-only cold boot
needs an out-of-band readiness signal; this contract does not define one.
The marker is cleared by the existing start/restore lifecycle. Sessions close at
the end of each public operation; all chunks of a file transfer share a session.
Mac serial sessions sharing a port are serialized across backend objects; Q800
retains its per-instance agent lock. Within a controller process, concurrent backend
operations cannot hold two sessions on the same serial port.

A generic `agent_call("screenshot", arguments)` returns one VA1 1.1 page. Use
`AgentClient.screenshot()` within one session when a complete image is needed; it
pages the retained capture and validates the assembled image. Use
`client.hello().kv["temp"]` for portable scratch paths rather than assuming `/tmp`.

Windows guests also listen on TCP 9009 with the guest firewall rule installed.
Win98 uses TCP only; virtio-serial concurrency uses separate numbered ports.

## Reference agent and conformance

`FakeAgent` serves an in-memory filesystem and process list. Configure `charset`,
`max_frame`, `tools`, `caps`, and `temp`. It never operates on the host filesystem, display,
processes or power state. `serve(socket)` accepts an owned stream; `connect(timeout)`
creates a socketpair; `listen()` yields a temporary loopback endpoint, and
`listen(path)` yields a Unix socket endpoint with one active stream per socket by
default; `one_stream=False` allows multiple streams for tests. Multiple listeners
on the same fake share reply and capture caches. The default screenshot spans
multiple pages at `max_frame=1024`; `screenshot` holds its `(format, width, height, bytes)`
fixture. Always call `close()` after socketpair
use. Listener context managers close their connections automatically.

```python
from vmctl_core.agentwire.fakeagent import FakeAgent

agent = FakeAgent(charset="macroman", max_frame=1024)
agent.inject("drop", tool="write_file")
with agent.listen() as endpoint:
    # Connect clients or invoke conformance against endpoint here.
    pass
```

Faults apply once to the next new call of the selected tool: `garbage` prefixes a
reply, `bad_crc` corrupts its CRC, `drop` disconnects after caching the completed
reply, and `slow` delays execution by `delay` seconds. Replays never repeat the work
or fault. All streams share the process-wide cache of 64 completed IDs.

```sh
python -m vmctl_core.agentwire.conformance 127.0.0.1:9009 --scratch /tmp
python -m vmctl_core.agentwire.conformance unix:/run/vm/channel.sock --scratch 'C:\Temp'
python -m vmctl_core.agentwire.conformance unix:/run/vm/lane.0 --second unix:/run/vm/lane.1
```

`--scratch` identifies an existing guest directory. The suite creates a random
child and removes only its own files and directory, even after a failed check.
The default is the guest's writable `hello temp` directory, in native syntax.
The runner prints PASS/FAIL/SKIP per check, includes totals, and exits 1 on any
failure. `conformance.run(client, scratch=None, second=None)` exposes the same results
as `Check` records for acceptance tooling; `second` is a keyword-only `AgentClient`
using a separate transport to the same guest process.

Stream recovery uses the primary leased connection. Cross-stream replay and
busy/liveness checks open another connection only on TCP. For Unix serial ports,
provide `--second unix:PATH` for a different port (such as lane `.1`); otherwise both
checks report SKIP with the one-stream limitation. Each Unix lane retains one
connection throughout the run. Custom socket factories also require an explicit
second client for cross-stream checks.

Checks cover hello, error codes, stream recovery, replay across connections,
busy/liveness using a safe sleep where available, binary and high-byte filename
round trips, chunking, reassembled image headers and advertised tool responses. Power, input,
process-killing and OS-specific mutations without a safe probe are explicitly
SKIP. A guest without a safe supported sleep cannot be tested for busy/liveness.
Unrecognized screenshot formats are SKIP rather than being called valid.
These skips mean a non-destructive run cannot certify every advertised tool.

`tests/agentwire_vectors/` contains the 14 upstream wire/output pairs unchanged,
plus a SHA-256 manifest covering both the vectors and codec. Refresh all three
together when deliberately updating the pinned contract. The tests exercise each
vector with five stream fragment sizes. Integration tests use memory streams,
socketpairs, TCP and Unix sockets. Restricted environments skip socket tests only
when socket operations raise `PermissionError`; the memory stream tests still run.
