"""Per-instance network capture (v1).

Captures a VM's traffic on its host tap device with tcpdump and reads it back
with tshark for display in the web UI. Capture needs root, so tcpdump/tshark run
via passwordless ``sudo -n`` (the controller host must allow it).

v1 = raw packet view. The richer layer (mitmproxy archive/replay, FakeNet/INetSim,
per-project wayback-cache-proxy) builds on top later (research/05).
"""

from __future__ import annotations

import contextlib
import os
import shlex
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

_FIELDS = [
    "frame.number",
    "frame.time_relative",
    "ip.src",
    "ip.dst",
    "_ws.col.Protocol",
    "frame.len",
    "_ws.col.Info",
]


class NetworkMonitor:
    def __init__(self, capture_dir: str | Path | Callable[[str], Path]) -> None:
        # Either one fixed dir for all instances, or a per-instance resolver
        # (``iid -> dir``) so the caller can route captures into per-artwork
        # storage (research/68) — the monitor itself stays layout-agnostic.
        if callable(capture_dir):
            self._dir_for: Callable[[str], Path] = capture_dir
        else:
            root = Path(capture_dir)
            self._dir_for = lambda iid: root
        self._procs: dict[str, subprocess.Popen] = {}
        # Per-instance lock so the check-then-spawn in start() (and the teardown in stop()) is
        # atomic: two concurrent start(iid) calls from the controller's threadpool must not both
        # pass is_capturing()==False and exec two tcpdumps onto the same <iid>.pcap (interleaved
        # writes corrupt the capture). Different instances still capture concurrently.
        self._start_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def _lock_for(self, iid: str) -> threading.Lock:
        with self._locks_guard:
            lk = self._start_locks.get(iid)
            if lk is None:
                lk = self._start_locks[iid] = threading.Lock()
            return lk

    def _dir(self, iid: str) -> Path:
        d = Path(self._dir_for(iid))
        d.mkdir(parents=True, exist_ok=True)
        return d

    def pcap_path(self, iid: str) -> Path:
        return self._dir(iid) / f"{iid}.pcap"

    def _pidfile(self, iid: str) -> Path:
        return self._dir(iid) / f"{iid}.pid"

    def is_capturing(self, iid: str) -> bool:
        p = self._procs.get(iid)
        if p is not None and p.poll() is None:
            return True
        # No live in-memory handle — but after a controller restart self._procs is
        # empty while a real sudo tcpdump may still be running. Reconcile against
        # the persisted pidfile so start() won't spawn a SECOND tcpdump onto the
        # same <iid>.pcap and corrupt it.
        return self._pidfile_alive(iid)

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        """True if `pid` is a live process. A sudo tcpdump runs as root, so a
        non-root controller gets EPERM from ``kill(pid, 0)`` — that still means
        the process EXISTS, so treat it as alive."""
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    def _pidfile_alive(self, iid: str) -> bool:
        """True only if the recorded pidfile names a still-alive process. A stale
        pidfile (crashed/killed capture) is removed so start() can proceed clean."""
        pidfile = self._pidfile(iid)
        if not pidfile.exists():
            return False
        try:
            pid = int(pidfile.read_text().strip())
        except (ValueError, OSError):
            return False
        if self._pid_alive(pid):
            return True
        pidfile.unlink(missing_ok=True)
        return False

    @staticmethod
    def _sanitize_bpf(expr: str) -> str:
        """Whitelist a caller-supplied BPF exclude so it can't inject shell or a
        malformed filter. Allows the small token set a port/host exclusion needs
        (``tcp``/``udp``/``port``/``host``/``and``/``or``/``not``/digits/dots/
        parens/whitespace). Anything else -> rejected (returns "")."""
        import re

        if not expr:
            return ""
        if not re.fullmatch(r"[A-Za-z0-9_.\s()]+", expr):
            return ""
        allowed = {"tcp", "udp", "port", "host", "and", "or", "not", "net", "ip"}
        for tok in re.findall(r"[A-Za-z_]+", expr):
            if tok.lower() not in allowed:
                return ""
        return expr.strip()

    def start(self, iid: str, tap: str, exclude: str | None = None) -> dict:
        """Start a per-instance pcap on ``tap``.

        ``exclude`` is an optional BPF sub-expression for traffic that must NEVER
        enter the pcap — e.g. the research/58 Mac OS 9 agent's HTTP port
        (``tcp port 9610``), so the conservator's stored capture stays clean of
        rvmc's own control traffic (research/58 §3.3). It is ANDed as
        ``and not ( <exclude> )`` into the tcpdump CAPTURE filter (authoritative —
        the frames are dropped at capture time, not just hidden in the UI). The
        spawner passes the helper's ``bpf_exclude`` here for mac9 instances; for
        every other guest ``exclude`` is empty and behaviour is unchanged.
        """
        with self._lock_for(iid):
            return self._start_locked(iid, tap, exclude)

    def _start_locked(self, iid: str, tap: str, exclude: str | None) -> dict:
        if self.is_capturing(iid):
            return self.status(iid)
        pcap = self.pcap_path(iid)
        pidfile = self._pidfile(iid)
        bpf = ""
        safe = self._sanitize_bpf(exclude or "")
        if safe:
            # The exclude is the SOLE filter expression (tcpdump gets no base filter),
            # so it must stand alone: `not ( <exclude> )`. A leading `and` would be a
            # binary operator with no left operand -> libpcap `pcap_compile` syntax error
            # -> tcpdump exits -> empty pcap (the same silent-no-capture symptom, moved
            # from the shell to the filter compiler).
            bpf = f"not ( {safe} )"
        # exec so the recorded pid IS tcpdump (clean kill of the root process).
        # The capture filter is passed to tcpdump as a POSITIONAL argument ("$@"),
        # never spliced into the `sh -c` script text. The BPF exclude contains shell
        # control operators — the grouping parens `( )` — so interpolated raw into the
        # script they parse as a subshell and `sh` aborts with 'Syntax error: "("
        # unexpected'; tcpdump then never execs and every excluded guest silently
        # captures nothing (DEVNULL hides the error). As a positional arg the shell
        # forwards it verbatim without re-parsing, and tcpdump takes the whole word as
        # its filter expression. Every interpolated value (paths, tap name) is
        # shell-quoted so a space / shell metacharacter in the capture dir / iid / tap
        # can't corrupt the redirect or inject into the root shell.
        script = (
            f"echo $$ > {shlex.quote(str(pidfile))}; "
            f'exec tcpdump -i {shlex.quote(str(tap))} -U -s 0 -w {shlex.quote(str(pcap))} "$@"'
        )
        argv = ["sudo", "-n", "sh", "-c", script, "sh"]
        if bpf:
            argv.append(bpf)
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self._procs[iid] = proc
        return self.status(iid)

    def stop(self, iid: str) -> dict:
        with self._lock_for(iid):
            return self._stop_locked(iid)

    @staticmethod
    def _pid_exited(proc: subprocess.Popen | None, pid: str, timeout: float) -> bool:
        """True once the root tcpdump ``pid`` is CONFIRMED gone (not merely signalled).

        With a live Popen handle a successful ``wait`` proves it — ``sudo`` outlives its
        tcpdump child, so its exit means the child exited. On the post-restart reconcile
        path there is no handle; a non-root ``os.kill(pid, 0)`` can't tell a ROOT process's
        liveness (EPERM = 'alive' either way), and ``sudo kill -0`` conflates 'no such
        process' with a sudo/exec failure. So poll ``/proc/<pid>`` instead — its existence
        is a privilege-free, unambiguous liveness signal on Linux (the deploy platform)."""
        if proc is not None:
            try:
                proc.wait(timeout=timeout)
                return True
            except subprocess.TimeoutExpired:
                return False
        if not pid.isdigit():
            return True  # no valid pid to track -> nothing we can keep alive
        procfs = Path("/proc") / pid
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not procfs.exists():
                return True  # /proc entry gone -> process exited
            time.sleep(0.05)
        return False

    def _stop_locked(self, iid: str) -> dict:
        proc = self._procs.pop(iid, None)
        pidfile = self._pidfile(iid)
        proc_live = proc is not None and proc.poll() is None
        # Read the recorded root pid ONCE into a local. The spawned shell writes it
        # ("echo $$ > pidfile") a beat AFTER Popen returns, and CREATES the file before
        # writing to it — so a start() immediately followed by stop() can see the pidfile
        # exist but still be EMPTY. While the capture proc is live, wait for a NON-EMPTY
        # pid so the kill path (and its timeout fallback) always target the real root pid
        # instead of giving up and leaking the tcpdump. The fallback uses this local, not
        # the pidfile (which we may unlink).
        pid = ""
        deadline = time.monotonic() + 1.0
        while True:
            if pidfile.exists():
                with contextlib.suppress(OSError):
                    pid = pidfile.read_text().strip()
            if pid or not proc_live or time.monotonic() >= deadline:
                break
            time.sleep(0.02)
            proc_live = proc is not None and proc.poll() is None

        # `dead` gates the pidfile removal: only unlink once the root tcpdump is provably
        # gone. While it may still be alive (kill failed / not yet exited) the pidfile
        # stays so is_capturing() reads True and a subsequent start() won't spawn a SECOND
        # tcpdump writing the same <iid>.pcap. An empty/absent pidfile with NO live proc =
        # nothing to kill (is_capturing() already treats an unparseable pidfile as
        # not-capturing); an empty pidfile WITH a live proc is the disk-anomaly case where
        # we can't target the pid, so we do NOT declare it dead.
        dead = not pid and not proc_live
        if pid:
            with contextlib.suppress(subprocess.TimeoutExpired):
                subprocess.run(
                    ["sudo", "-n", "kill", pid], capture_output=True, text=True, timeout=5
                )
            # Do NOT trust SIGTERM delivery as proof of death — CONFIRM the tcpdump is
            # actually gone (a running process being unlinked would let an immediate
            # start() double-write the pcap). With a Popen handle a successful wait proves
            # it; on the reconcile path (no handle) probe the pid as root (see _pid_exited).
            dead = self._pid_exited(proc, pid, timeout=5.0)
            if not dead:
                # SIGTERM didn't reap it: hard-kill the recorded root pid via sudo (proc.kill
                # would only SIGKILL the unprivileged `sudo` wrapper, never the reparented
                # root tcpdump), then re-confirm.
                with contextlib.suppress(Exception):
                    subprocess.run(
                        ["sudo", "-n", "kill", "-9", pid],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                dead = self._pid_exited(proc, pid, timeout=5.0)
            if dead and proc is not None:
                with contextlib.suppress(Exception):
                    proc.kill()  # reap the sudo wrapper if it's still lingering
        if dead:
            pidfile.unlink(missing_ok=True)
        elif proc is not None and proc.poll() is None:
            # Couldn't confirm the capture stopped (kill failed, or the pid was never
            # recorded): keep tracking the still-live proc so is_capturing() stays True
            # (via self._procs) and a retry can target it — never drop the handle and let
            # status() misreport a live capture as stopped, which would let start()
            # double-spawn onto the same pcap.
            self._procs[iid] = proc
        return self.status(iid)

    def status(self, iid: str) -> dict:
        pcap = self.pcap_path(iid)
        return {
            "capturing": self.is_capturing(iid),
            "pcap": pcap.name if pcap.exists() else None,
            "size_bytes": pcap.stat().st_size if pcap.exists() else 0,
        }

    def recent(self, iid: str, count: int = 100) -> list[dict]:
        """Last `count` packets parsed from the pcap (newest last)."""
        return self._read(iid, display_filter=None, count=count)

    def search(self, iid: str, display_filter: str, count: int = 200) -> list[dict]:
        """Packets matching a tshark display filter — lets the AI 'catch' specific
        traffic (e.g. 'http', 'dns', 'ip.addr==1.2.3.4', 'tcp.port==443')."""
        return self._read(iid, display_filter=display_filter, count=count)

    def _read(self, iid: str, display_filter: str | None, count: int) -> list[dict]:
        pcap = self.pcap_path(iid)
        if not pcap.exists():
            return []
        cmd = [
            "sudo",
            "-n",
            "tshark",
            "-r",
            str(pcap),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=f",
        ]
        if display_filter:
            cmd += ["-Y", display_filter]
        for f in _FIELDS:
            cmd += ["-e", f]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if p.returncode != 0 and display_filter:
            raise ValueError(
                f"bad display filter: {p.stderr.strip().splitlines()[-1] if p.stderr.strip() else 'tshark error'}"
            )
        rows: list[dict] = []
        for line in p.stdout.splitlines():
            c = line.split("\t")
            if len(c) < len(_FIELDS):
                c += [""] * (len(_FIELDS) - len(c))
            rows.append(
                {
                    "no": c[0],
                    "time": c[1],
                    "src": c[2],
                    "dst": c[3],
                    "proto": c[4],
                    "len": c[5],
                    "info": c[6],
                }
            )
        return rows[-count:]

    # === capture_summary (research/31): digest, not packet dump =============
    # "What does this artwork try to reach?" — the conservation question. The raw
    # packet views (recent/search) stay for drilling in; this collapses the pcap
    # into an AI-readable digest: HTTP req/resp, DNS name->answer, TLS SNI (the
    # https hostnames even though encrypted), notable non-web peers, and counts.
    # Cheap: parses the already-captured file, never re-captures.

    # web/control-plane peers we de-emphasise in `other` (still counted)
    _WEB_PORTS: ClassVar = {80, 443, 8080, 8443}

    def _tshark_fields(
        self,
        pcap: Path,
        display_filter: str,
        fields: list[str],
        occurrence: str = "f",
        aggregator: str | None = None,
    ) -> list[list[str]]:
        """Run a -T fields query and return rows as lists of column strings.

        When ``occurrence="a"`` (all occurrences of a field, e.g. the many
        header lines of ``http.request.line``) pass an ``aggregator`` such as
        ``"~~"`` so multi-valued cells are joined with a delimiter that won't
        collide with commas inside header values; callers then split on it.
        """
        cmd = [
            "sudo",
            "-n",
            "tshark",
            "-r",
            str(pcap),
            "-T",
            "fields",
            "-E",
            "separator=\t",
            "-E",
            "occurrence=" + occurrence,
        ]
        if aggregator is not None:
            cmd += ["-E", "aggregator=" + aggregator]
        cmd += ["-Y", display_filter]
        for f in fields:
            cmd += ["-e", f]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        rows: list[list[str]] = []
        for line in p.stdout.splitlines():
            c = line.split("\t")
            if len(c) < len(fields):
                c += [""] * (len(fields) - len(c))
            rows.append(c)
        return rows

    # === HTTP transactions: the proper request<->response binding ==========
    # The old digest paired req/resp by tcp.stream, which is wrong under
    # HTTP keep-alive (many req/resp per stream) and pipelining. tshark already
    # solves the matching: every response frame carries ``http.request_in`` (the
    # frame number of *its* request) and every request carries
    # ``http.response_in``. We pair on those exact frame links — no guessing —
    # and emit real transactions the conservator can expand in the UI.

    # tshark only honours the FIRST char of -E aggregator, so it can't be a
    # token guaranteed absent from header values. We don't rely on it for
    # splitting: every header line tshark emits ends in a literal "\r\n", so we
    # split on that and just discard the leading aggregator byte per line.
    _AGG = "|"

    # request-side fields (one row per request frame)
    _REQ_FIELDS: ClassVar = [
        "frame.number",
        "frame.time_epoch",
        "http.response_in",
        "http.request.method",
        "http.host",
        "http.request.uri",
        "http.request.full_uri",
        "ip.dst",
        "tcp.stream",
    ]
    # response-side fields (one row per response frame)
    _RESP_FIELDS: ClassVar = [
        "frame.number",
        "frame.time_epoch",
        "http.request_in",
        "http.response.code",
        "http.response.phrase",
        "http.content_type",
        "http.content_length",
        "http.location",
        "ip.src",
        "tcp.stream",
    ]

    @staticmethod
    def _split_headers(cell: str, sep: str) -> list[str]:
        """A raw ``http.*.line`` cell -> clean list of "Name: value" strings.

        tshark joins the many header lines into one cell; each line ends in a
        literal CRLF which tshark renders as the four characters ``\\r\\n``. We
        split on that boundary (robust even though the aggregator char is only
        a single byte), then strip any stray CR/LF and the aggregator byte.
        """
        out: list[str] = []
        for h in cell.split("\\r\\n"):
            # strip CR/LF residue (raw + tshark's escaped "\r"/"\n" text), then
            # the leading aggregator byte that joins the second header line on
            h = h.replace("\\r", "").replace("\\n", "").replace("\r", "").replace("\n", "").strip()
            h = h.lstrip(sep).strip()
            if h:
                out.append(h)
        return out

    @staticmethod
    def _headers_to_dict(lines: list[str]) -> dict[str, str]:
        d: dict[str, str] = {}
        for ln in lines:
            name, _, val = ln.partition(":")
            name = name.strip()
            if name:
                d[name] = val.strip()
        return d

    @staticmethod
    def _archive_marker(headers: dict[str, str]) -> dict | None:
        """Detect a wbc/wayback-cache-proxy served response (vs a live fetch).

        The per-project wbc proxy stamps replayed responses with
        ``X-Wayback-Timestamp`` / ``X-Wayback-URL`` (and generic archives use
        ``Memento-Datetime`` / ``X-Archive-*``). Surface that so the UI can show
        "served from archive @ <when>" instead of pretending it's live.
        """
        ci = {k.lower(): v for k, v in headers.items()}
        ts = ci.get("x-wayback-timestamp") or ci.get("memento-datetime")
        url = ci.get("x-wayback-url") or ci.get("x-archive-orig-location")
        if ts or url or "x-archive-src" in ci or "x-cache" in ci:
            m: dict[str, str] = {}
            if ts:
                m["timestamp"] = ts
            if url:
                m["url"] = url
            if "x-cache" in ci:
                m["cache"] = ci["x-cache"]
            return m
        return None

    def _http_transactions(self, pcap: Path, max_items: int, with_bodies: bool) -> list[dict]:
        """Build properly-bound HTTP transactions from the pcap.

        Pairs each response to its request via ``http.request_in`` (and falls
        back to ``http.response_in`` from the request side, then to a
        per-stream FIFO queue only for the rare frame with no link at all).
        Returns up to ``max_items`` transactions newest-request-first reversed
        to request order, each shaped as::

            {request:{frame,method,host,path,url,headers[],...},
             response:{frame,status,reason,content_type,length,headers[],
                       body_preview?,archived?},
             timing:{request_ts,response_ts,elapsed_ms}}
        """
        # request rows (+ headers as a separate all-occurrence query)
        req_rows = self._tshark_fields(pcap, "http.request", self._REQ_FIELDS)
        req_hdr_rows = self._tshark_fields(
            pcap,
            "http.request",
            ["frame.number", "http.request.line"],
            occurrence="a",
            aggregator=self._AGG,
        )
        req_hdrs = {r[0]: self._split_headers(r[1], self._AGG) for r in req_hdr_rows}

        resp_rows = self._tshark_fields(pcap, "http.response", self._RESP_FIELDS)
        resp_hdr_rows = self._tshark_fields(
            pcap,
            "http.response",
            ["frame.number", "http.response.line"],
            occurrence="a",
            aggregator=self._AGG,
        )
        resp_hdrs = {r[0]: self._split_headers(r[1], self._AGG) for r in resp_hdr_rows}

        body_map: dict[str, str] = {}
        if with_bodies:
            body_rows = self._tshark_fields(
                pcap, "http.response && http.file_data", ["frame.number", "http.file_data"]
            )
            body_map = {r[0]: r[1] for r in body_rows}

        # index requests by frame number, keep capture order
        requests: dict[str, dict] = {}
        order: list[str] = []
        stream_reqs: dict[str, list[str]] = {}  # stream -> unmatched req frames (FIFO)
        for fno, ts, resp_in, method, host, uri, full_uri, dst, stream in req_rows:
            lines = req_hdrs.get(fno, [])
            requests[fno] = {
                "frame": int(fno) if fno.isdigit() else fno,
                "method": method,
                "host": host,
                "path": uri,
                "url": full_uri or (f"http://{host}{uri}" if host and uri else uri),
                "headers": lines,
                "header_map": self._headers_to_dict(lines),
                "dst": dst,
                "stream": stream,
                "_ts": ts,
                "_response_in": resp_in,
            }
            order.append(fno)
            stream_reqs.setdefault(stream, []).append(fno)

        # attach responses to their request via http.request_in
        responses: dict[str, dict] = {}  # req-frame -> response dict
        for fno, ts, req_in, code, phrase, ctype, clen, location, _src, stream in resp_rows:
            lines = resp_hdrs.get(fno, [])
            hdr_map = self._headers_to_dict(lines)
            content_type = ctype.split(";")[0].strip() if ctype else ""
            resp = {
                "frame": int(fno) if fno.isdigit() else fno,
                "status": int(code) if code.isdigit() else (code or None),
                "reason": phrase or None,
                "content_type": content_type,
                "length": int(clen) if clen.isdigit() else None,
                "location": location or None,
                "headers": lines,
                "header_map": hdr_map,
                "archived": self._archive_marker(hdr_map),
                "_ts": ts,
            }
            if with_bodies and fno in body_map:
                resp["body_preview"] = self._decode_body(body_map[fno], content_type)
            # primary binding: the response names its request frame
            key = req_in if req_in in requests else None
            if key is None and stream in stream_reqs and stream_reqs[stream]:
                # fallback: oldest still-unmatched request on this stream
                key = stream_reqs[stream][0]
            if key is not None:
                responses[key] = resp
                if stream in stream_reqs and key in stream_reqs[stream]:
                    stream_reqs[stream].remove(key)

        txns: list[dict] = []
        # Keep the NEWEST max_items (tail of capture order), not the oldest — a
        # long-running capture should surface current traffic, matching recent()'s
        # rows[-count:]. Chronological (request) order within the window is preserved.
        for fno in order[-max_items:]:
            req = requests[fno]
            bound = responses.get(fno)
            timing = {
                "request_ts": self._as_float(req.get("_ts")),
                "response_ts": self._as_float(bound.get("_ts")) if bound else None,
                "elapsed_ms": None,
            }
            if timing["request_ts"] is not None and timing["response_ts"] is not None:
                timing["elapsed_ms"] = round(
                    (timing["response_ts"] - timing["request_ts"]) * 1000, 1
                )
            # strip internal bookkeeping before emit
            req_out = {
                k: v for k, v in req.items() if k not in ("_ts", "_response_in", "header_map")
            }
            resp_out = None
            if bound:
                resp_out = {k: v for k, v in bound.items() if k not in ("_ts", "header_map")}
            txns.append(
                {
                    "request": req_out,
                    "response": resp_out,
                    "timing": timing,
                    "archived": bool(resp_out and resp_out.get("archived")),
                }
            )
        return txns

    @staticmethod
    def _as_float(s) -> float | None:
        try:
            return float(s)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _decode_body(hexstr: str, content_type: str, limit: int = 2048) -> dict:
        """Decode an ``http.file_data`` hex blob into a previewable snippet.

        Text-ish bodies are decoded to a UTF-8 (lossy) string and truncated;
        binary bodies report their size only (no point dumping image bytes).
        """
        raw = b""
        with contextlib.suppress(ValueError):
            raw = bytes.fromhex(hexstr.replace(":", ""))
        ct = (content_type or "").lower()
        textish = (
            ct.startswith("text/")
            or "json" in ct
            or "xml" in ct
            or "javascript" in ct
            or "html" in ct
            or "css" in ct
            or "ecmascript" in ct
            or ct == ""
        )
        out: dict[str, Any] = {
            "bytes": len(raw),
            "text": None,
            "truncated": False,
            "binary": not textish,
        }
        if textish and raw:
            snippet = raw[:limit]
            out["truncated"] = len(raw) > limit
            out["text"] = snippet.decode("utf-8", "replace")
        return out

    def transactions(self, iid: str, max_items: int = 200, with_bodies: bool = True) -> dict:
        """Properly-bound HTTP request<->response transactions for the UI.

        Standalone endpoint (heavier than ``summarize``: pulls headers + body
        previews) so the devtools-style Requests view can show what actually
        came back and whether it was served live or from the wbc archive.
        """
        pcap = self.pcap_path(iid)
        if not pcap.exists() or pcap.stat().st_size == 0:
            return {"transactions": [], "pcap": None}
        return {
            "transactions": self._http_transactions(pcap, max_items, with_bodies=with_bodies),
            "pcap": pcap.name,
        }

    def summarize(self, iid: str, max_items: int = 50) -> dict:
        """Compact digest of a VM's captured traffic for the AI / conservation UI.

        Returns {http, transactions, dns, tls_sni, other, conversations,
        counts, pcap}. ``transactions`` is the properly-bound request->response
        view (see ``_http_transactions``); ``http`` is the flat request-centric
        list kept for the host roll-up / anomaly flags.
        """
        pcap = self.pcap_path(iid)
        empty: dict[str, Any] = {
            "http": [],
            "transactions": [],
            "dns": [],
            "tls_sni": [],
            "other": [],
            "conversations": [],
            "counts": {},
            "pcap": None,
        }
        if not pcap.exists() or pcap.stat().st_size == 0:
            return empty

        # --- HTTP: real request<->response binding via http.request_in ----
        # (no tcp.stream guessing — keep-alive/pipelining safe). Bodies are
        # omitted here to keep the digest small; the detail view fetches them.
        txns = self._http_transactions(pcap, max_items, with_bodies=False)
        # flat request-centric list for the host roll-up + anomaly flags
        http = []
        for t in txns:
            req, resp = t["request"], t.get("response")
            http.append(
                {
                    "host": req.get("host", ""),
                    "method": req.get("method", ""),
                    "path": req.get("path", ""),
                    "status": resp.get("status") if resp else None,
                    "type": (resp.get("content_type") if resp else "") or "",
                    "redirect": (resp.get("location") if resp else None) or None,
                }
            )

        # --- DNS: name -> answers (A records + CNAME), de-duped ------------
        dns_rows = self._tshark_fields(
            pcap, "dns.flags.response==1", ["dns.qry.name", "dns.a", "dns.cname"], occurrence="a"
        )
        dns_map: dict[str, set] = {}
        for name, a, cname in dns_rows:
            if not name:
                continue
            ans = dns_map.setdefault(name, set())
            for v in (a + "," + cname).split(","):
                v = v.strip()
                if v:
                    ans.add(v)
        dns = [{"name": n, "answers": sorted(a)} for n, a in sorted(dns_map.items())][:max_items]

        # --- TLS SNI: the https hostnames (encrypted payload, clear SNI) ---
        sni_rows = self._tshark_fields(
            pcap,
            "tls.handshake.extensions_server_name",
            ["tls.handshake.extensions_server_name"],
            occurrence="a",
        )
        sni = sorted({c[0].strip() for c in sni_rows if c[0].strip()})[:max_items]

        # --- conversations + non-web peers via conv,tcp -------------------
        conversations, other = self._conversations(pcap, max_items)

        # --- protocol hierarchy counts (the 'something else' radar) -------
        counts = self._proto_counts(pcap)
        counts.update(
            {"http_requests": len(http), "dns_names": len(dns_map), "tls_sni_hosts": len(sni)}
        )

        return {
            "http": http,
            "transactions": txns,
            "dns": dns,
            "tls_sni": sni,
            "other": other,
            "conversations": conversations,
            "counts": counts,
            "pcap": pcap.name,
        }

    def _conversations(self, pcap: Path, max_items: int) -> tuple[list[dict], list[dict]]:
        """Parse `tshark -z conv,tcp` into per-peer rows; flag non-web peers."""
        p = subprocess.run(
            ["sudo", "-n", "tshark", "-r", str(pcap), "-q", "-z", "conv,tcp"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        conversations: list[dict] = []
        for line in p.stdout.splitlines():
            if "<->" not in line:
                continue
            parts = line.split()
            try:
                i = parts.index("<->")
            except ValueError:
                continue
            left, right = parts[i - 1], parts[i + 1]
            # totals are columns 5/6 after the two endpoints: frames + value+unit
            tail = parts[i + 2 :]
            total_bytes, total_frames = self._conv_totals(tail)
            peer_ip, peer_port = self._split_hostport(right)
            conversations.append(
                {
                    "peer": peer_ip,
                    "port": peer_port,
                    "bytes": total_bytes,
                    "frames": total_frames,
                    "local": left,
                }
            )
        conversations.sort(key=lambda c: c["bytes"], reverse=True)
        other = [c for c in conversations if c["port"] not in self._WEB_PORTS][:max_items]
        return conversations[:max_items], other

    @staticmethod
    def _split_hostport(s: str) -> tuple[str, int]:
        host, _, port = s.rpartition(":")
        if not host:
            return s, 0
        try:
            return host, int(port)
        except ValueError:
            return s, 0

    @staticmethod
    def _conv_totals(tail: list[str]) -> tuple[int, int]:
        """From the conv,tcp row tail, pull the 'Total' frames+bytes (cols 5/6).
        Layout per endpoint pair: <-frames <-bytes unit -> frames ->bytes unit
        total_frames total_bytes unit  start  duration."""
        # collect (number, optional-unit) tokens; the Total pair is the 3rd group
        units = {"bytes": 1, "kB": 1000, "MB": 1000000, "GB": 1000000000}
        nums: list[float] = []
        i = 0
        while i < len(tail):
            t = tail[i]
            try:
                n = float(t)
            except ValueError:
                i += 1
                continue
            mult = 1
            if i + 1 < len(tail) and tail[i + 1] in units:
                mult = units[tail[i + 1]]
                i += 1
            nums.append(n * mult)
            i += 1
        # nums ~= [<-frames,<-bytes, ->frames,->bytes, totframes,totbytes, start,dur]
        if len(nums) >= 6:
            return int(nums[5]), int(nums[4])
        if len(nums) >= 2:
            return int(nums[-1]), int(nums[0])
        return 0, 0

    def _proto_counts(self, pcap: Path) -> dict:
        """Frame counts per protocol from `-z io,phs` (the 'else' radar)."""
        p = subprocess.run(
            ["sudo", "-n", "tshark", "-r", str(pcap), "-q", "-z", "io,phs"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        counts: dict[str, int] = {}
        for line in p.stdout.splitlines():
            s = line.strip()
            if not s or "frames:" not in s:
                continue
            proto = s.split()[0]
            try:
                frames = int(s.split("frames:")[1].split()[0])
            except (IndexError, ValueError):
                continue
            # a proto can appear at several nesting depths (e.g. tls directly on
            # tcp AND under tcp.segments); keep the larger = the real frame total
            counts[proto] = max(counts.get(proto, 0), frames)
        return counts
