"""Classic Mac OS System 7 on 68k (q800 / Quadra 800) — research/70b, 70c.

The agent is ``rvmc-agent-68k`` (vmctl-guest-agent/mac68k): a Retro68 C application
on MacTCP, autostarted by an alias in Startup Items. It speaks VA1 on TCP 9009
and the ESCC printer port. The q800 backend reaches it through SLiRP or serial
(``Q800Backend.agent_call``).

What it is NOT: there is no interpreter and no shell in the guest. ``exec``/``python``
/``run_shell`` do not exist; the controller turns a "run" into ``run_app {path}``
(Finder ``aevt/odoc``, i.e. a double-click). So unlike the mac9 module this one
declares no in-guest code runtime.
"""

from __future__ import annotations

from ..capabilities import Capabilities, Capability
from ..contract import BaseGuestOSModule, LogRecord

# The agent logs to System Folder:Preferences (NOT next to the app: the Finder "opens"
# every document in Startup Items at boot). Boot volume name of the q800 golden.
AGENT_LOG = "Macintosh HD:System Folder:Preferences:rvmc-agent68k.log"


class MacOS7Module(BaseGuestOSModule):
    os_labels: tuple[str, ...] = ("system-7", "system-6")
    display_name = "System 7 (68k Mac)"

    def caps(self) -> Capabilities:
        # AGENT: rvmc-agent-68k (files, processes, run_app, keys, absolute mouse,
        #   screenshot). READ_LOGS: the agent's own log via read_file.
        # MAKE_GOLDEN: vmctl-guest-agent/mac68k/golden/build-golden.sh.
        # NOT DATALINK_MOUNT: the datalink CD is ISO9660 and the q800 CD path mounts only
        #   APM/HFS discs (70b §3.3); files go through the agent's write_file instead.
        return Capabilities.of(Capability.AGENT, Capability.READ_LOGS, Capability.MAKE_GOLDEN)

    def agent_transport(self, ctx) -> str:
        return "tcp"

    def read_logs(self, ctx, *, kind: str = "agentbox", count: int = 50) -> list[LogRecord]:
        try:
            raw = ctx.guest_read_file(AGENT_LOG)
        except Exception as e:
            return [
                LogRecord(source="rvmc-agent68k", level="warning", message=f"(unavailable: {e})")
            ]
        text = raw.decode("mac-roman", "replace")
        lines = [
            ln for ln in text.replace("\r\n", "\n").replace("\r", "\n").split("\n") if ln.strip()
        ]
        if count and count > 0:
            lines = lines[-count:]
        return [LogRecord(source="rvmc-agent68k", message=ln) for ln in lines]

    def make_golden_steps(self) -> list[str]:
        return [
            "emulator image vmctl-emu/qemu-m68k (QEMU -M q800, pinned by image id) + Quadra 800 "
            "ROM F1ACAD13 (host prerequisite)",
            "System 7.5.3 Easy Install from Apple CD 691-1079-A on an APM disk initialised by "
            "Apple HD SC Setup 7.3.5; PRAM with 32-bit addressing ships with the golden (hw.nvram)",
            "rvmc-agent-68k in Macintosh HD:rvmc:, alias in Startup Items, IdleStop in Extensions, "
            "MacTCP Ethernet/BOOTP, AppleTalk inactive (frees the printer port), shut-down warning "
            "off (vmctl-guest-agent/mac68k/golden/build_golden.py)",
        ]
