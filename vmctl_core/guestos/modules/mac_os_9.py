"""Classic Mac OS 9 reference module.

The faceless MacPython agent speaks VA1 over TCP 9009 on the libvirt NAT.
The controller resolves the guest IP and supplies a GuestContext returning VA1
Reply objects and chunked raw file reads. This module stays transport-independent.

Capability vs tools: the ``Capability`` enum is for cross-OS *behaviours* the
controller branches on (event log, NSS-CA, netsh, resolution API). Mac OS 9 has
none of those Windows-shaped ones — they correctly stay OFF. What it DOES now have
is generic text logs (``READ_LOGS``): the agent lifecycle log, the crash breadcrumb,
and live diagnostics. The agent's per-tool surface is otherwise advertised by the
agent itself and gated by ``AGENT``; ``gate_by_agent`` strips both AGENT and
READ_LOGS again on a stub (agentless) base, so a pre-research/64 golden degrades to
the old datalink-only stub exactly as before.

It also flags the BACKEND boundary: the mac9 guest runs under qemu-system-ppc
(mac99, sungem NIC on the libvirt NAT) — a real libvirt domain, NOT SheepShaver /
Basilisk II. The GuestOS module stays separate from that VMBackend concern.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, LogRecord

# Agent log/breadcrumb locations on the guest (classic colon paths). The agents
# write these under the MacPython folder; they are fetched verbatim via read_file.
_AGENT_DIR = "Ohne Titel:Applications (Mac OS 9):MacPython-OS9 2.3.3"
_FACELESS_LOG = _AGENT_DIR + ":rvmc_faceless.log"
_CTL_LOG = _AGENT_DIR + ":rvmc_ctl.log"
_BREADCRUMB = _AGENT_DIR + ":rvmc_breadcrumb.txt"


def _split_lines(text: str) -> list[str]:
    """Split on any classic/unix/dos line ending. The mac9 agents write CR (\\r)
    line ends; logs may also contain LF or CRLF, so normalise all three."""
    return text.replace("\r\n", "\n").replace("\r", "\n").split("\n")


def _tail(lines: list[str], count: int) -> list[str]:
    return lines[-count:] if count and count > 0 else lines


class MacOS9Module(BaseGuestOSModule):
    os_labels: tuple[str, ...] = ("mac-os-9", "macos9", "mac-os", "system-8")
    # System 7 (68k, q800) has its own module: mac_os_7.MacOS7Module
    display_name = "Mac OS 9 / Classic"

    def caps(self) -> Capabilities:
        # DATALINK_MOUNT: the universal host->guest CD (always available).
        # AGENT: the faceless MacPython VA1 agent on TCP :9009
        #   on the libvirt NAT. gate_by_agent() drops AGENT
        #   (and READ_LOGS, which rides the agent) for a mac9 base baked WITHOUT the
        #   agent (agent:false), so the old stub goldens degrade exactly as before.
        # READ_LOGS: generic text logs — agentbox lifecycle log, crash breadcrumb,
        #   and live diagnostics — read through read_logs() below via the agent.
        # MAKE_GOLDEN: documented golden recipe (make_golden_steps below).
        # NOT declared: read_event_log / install_ca* / configure_proxy|browser /
        #   set_resolution — those Windows-shaped behaviours don't exist on OS 9.
        return Capabilities.of(
            Capability.DATALINK_MOUNT,
            Capability.AGENT,
            Capability.READ_LOGS,
            Capability.MAKE_GOLDEN,
        )

    def agent_transport(self, ctx) -> str:
        # VA1 TCP on the libvirt NAT; the controller resolves the guest IP.
        return "tcp"

    # --- logs ---------------------------------------------------------------
    def read_logs(self, ctx, *, kind: str = "agentbox", count: int = 50) -> list[LogRecord]:
        """Generic text logs for Mac OS 9, via the faceless agent (read_file/run_script).

        kinds:
          agentbox    -> the agent lifecycle log rvmc_faceless.log (+ rvmc_ctl.log):
                         launch/warmup/serve/die/tracebacks.
          breadcrumb  -> rvmc_breadcrumb.txt parsed into UP/DOWN records; an
                         ``UP ... prev=DIRTY`` (last run force-killed/crashed) is
                         marked level=warning so the viewer can flag it.
          diagnostics -> live Gestalt system info + memory (MaxBlock/FreeMem) +
                         the Finder process roster, computed in-guest via run_script.
        """
        kind = (kind or "agentbox").lower()
        if kind == "breadcrumb":
            return self._read_breadcrumb(ctx, count)
        if kind == "diagnostics":
            return self._read_diagnostics(ctx)
        return self._read_agentbox(ctx, count)

    # --- agentbox: lifecycle logs (read_file, tail) -------------------------
    def _read_file_text(self, ctx, path: str) -> str:
        """Fetch all raw VA1 file chunks and decode classic Mac text."""
        return ctx.guest_read_file(path).decode("mac-roman", "replace")

    def _read_agentbox(self, ctx, count: int) -> list[LogRecord]:
        out: list[LogRecord] = []
        for path, src in ((_FACELESS_LOG, "rvmc_faceless"), (_CTL_LOG, "rvmc_ctl")):
            try:
                text = self._read_file_text(ctx, path)
            except Exception as e:
                out.append(LogRecord(source=src, level="warning", message=f"(unavailable: {e})"))
                continue
            lines = [ln for ln in _split_lines(text) if ln.strip()]
            for ln in _tail(lines, count):
                out.append(LogRecord(source=src, message=ln))
        return out

    # --- breadcrumb: UP/DOWN crash record -----------------------------------
    def _read_breadcrumb(self, ctx, count: int) -> list[LogRecord]:
        try:
            text = self._read_file_text(ctx, _BREADCRUMB)
        except Exception as e:
            return [LogRecord(source="breadcrumb", level="warning", message=f"(unavailable: {e})")]
        out: list[LogRecord] = []
        for ln in _tail([line for line in _split_lines(text) if line.strip()], count):
            level = ""
            # "UP <time> prev=DIRTY" = the previous session was force-killed/crashed.
            if ln.startswith("UP ") and "prev=DIRTY" in ln:
                level = "warning"
            out.append(LogRecord(source="breadcrumb", level=level, message=ln))
        return out

    # --- diagnostics: live Gestalt + memory + process roster (run_script) ---------
    # STRICT Python 2.3 — runs inside MacPython 2.3.3. The agent's run_script captures
    # stdout in Reply.kv["stdout"]; we print one human line per fact (no json module on
    # 2.3 by default). gestalt is a top-level builtin module here (not Carbon).
    _DIAG_PY = (
        "import sys\n"
        "def _g(sel):\n"
        "    try:\n"
        "        import gestalt\n"
        "        return gestalt.gestalt(sel)\n"
        "    except:\n"
        "        return None\n"
        "print 'runtime: MacPython %s' % sys.version.split()[0]\n"
        "print 'sysver: %r' % _g('sysv')\n"
        "print 'ram: %r' % _g('ram ')\n"
        "try:\n"
        "    import MacOS\n"
        "    print 'free_mem: %s' % MacOS.FreeMem()\n"
        "    print 'max_block: %s' % MacOS.MaxBlock()\n"
        "except:\n"
        "    print 'free_mem: (unavailable)'\n"
        "try:\n"
        "    import findertools\n"
        "    procs = findertools.processes()\n"
        "    print 'processes: %d' % len(procs)\n"
        "    for p in procs:\n"
        "        try:\n"
        "            print 'proc: %s (%s)' % (p[0], p[1])\n"
        "        except:\n"
        "            print 'proc: %r' % (p,)\n"
        "except:\n"
        "    print 'processes: (unavailable)'\n"
    )

    def _read_diagnostics(self, ctx) -> list[LogRecord]:
        try:
            res = ctx.guest_call("run_script", lang="python", code=self._DIAG_PY, timeout=40).kv
        except Exception as e:
            return [
                LogRecord(
                    source="diagnostics",
                    level="warning",
                    message=f"(diagnostics unavailable: {e})",
                )
            ]
        if res.get("exit") != "0":
            return [
                LogRecord(
                    source="diagnostics",
                    level="error",
                    message="run_script failed: %s" % (res.get("stderr") or "?"),
                )
            ]
        out_text = res.get("stdout") or ""
        recs: list[LogRecord] = []
        for ln in _split_lines(out_text):
            if not ln.strip():
                continue
            level = "warning" if ln.startswith("proc:") and "unavailable" in ln else ""
            recs.append(LogRecord(source="diagnostics", level=level, message=ln))
        if not recs:
            recs.append(LogRecord(source="diagnostics", message="(no diagnostics output)"))
        return recs

    def make_golden_steps(self) -> list[str]:
        return [
            "qemu-system-ppc -M mac99,via=cuda+usb_tablet -cpu g4 (OpenBIOS, no Mac ROM)",
            "install/clone Mac OS 9.2.2 (SheepShaver cannot run 9.2.x)",
            "audio requires the qemu screamer fork; stock qemu boots silent",
            "put the sungem NIC on the libvirt NAT (default net) for guest networking",
            "bake the faceless MacPython VA1 agent (TCP :9009) "
            "into System Folder > Startup Items so it autostarts "
            "headless; set the base agent:true to light the "
            "AGENT + READ_LOGS capabilities",
        ]
