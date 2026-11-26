# Read-only guest introspection

`ProcessSpec.probe` enables guest liveness without an installed guest agent. Omit it
(or use `null`) to keep process/alive-file liveness unchanged.

Amiga example within `process.json`:

```json
"probe": {
  "kind": "amiga",
  "kickstart": "roms/kick.rom",
  "expect": ["proj2"],
  "max_age_s": 10
}
```

The Kickstart path resolves against the instance directory, independently of `cwd`.
Include the ROM in the instance's existing `media` or `images` configuration when
cloning or bundling. For MAME classic Mac OS, use:

```json
"probe": {"kind": "mac68k", "ram_bytes": 16777216, "expect": ["Finder"]}
```

Amiga discovery uses the Kickstart `exec.library` pointer, ExecBase's complement
checksum, and MemList headers to locate independently allocated RAM banks. Samples
include ThisTask, TaskReady, TaskWait, CLI commands, ports, libraries and devices.
List walks validate predecessors and the tail, retry torn reads, and cap traversal.
MAME RAM discovery checks ROMBase and CurApName; reads convert host-endian 32-bit
words before interpreting unaligned big-endian low-memory globals.

`guest_ping()` compares consecutive samples. Amiga uses the counter at
`vmctl.heartbeat` port + 34 when present, otherwise DispCount; Mac uses Ticks.
Every expected name must also be present. Matches are case-insensitive and exact;
Amiga accepts task names, full CLI paths and CLI basenames (`proj2` matches
`dh0:orpheus/oc/proj2`). Mac can only report the current application, not background
processes. Counter wraparound is accepted; backward jumps/resets are not progress.
Equal values between polls remain alive for `max_age_s` after the last observed
progress. A changed value updates the baseline even after a long polling gap. A
backward jump/reset records a change but requires subsequent progress to be alive.

A new process identity/counter source/configuration returns `alive=None` and
`reason="warming up"` until the first change or `max_age_s` since attachment.
Without a change by that deadline, `introspect.liveness.probe` returns false. `guest_ping()` maps this to false to retain its boolean
backend contract. If `alive_file` is configured, it must also pass its existing age
check. `guest_tasks()` returns the latest probe detail, including task data and the
tri-state `alive`; its first call samples, and later calls use the sample obtained
by `guest_ping()` without advancing the counter baseline. This detail describes the
memory probe; the optional alive-file condition applies separately to `guest_ping()`.

The backend starts its search at `process.emulator.pid` with `virtual_display`, or
`process.pid` otherwise. Either PID can be a wrapper script. It searches that
process's group and all descendants (including children in new groups), prioritizing
`fs-uae` and the
basename of `argv[0]` (limited to Linux comm's 15 bytes), then trying other members
in PID order. A successful RAM attachment selects the owner for subsequent calls.
State belongs to each backend instance and checks Linux process starttime to reject
PID reuse. Each call closes its `/proc/PID/mem` descriptor.

All process-memory access uses `os.open(..., os.O_RDONLY)` and `os.pread`; probes
never write, pause or signal the emulator. Unreadable memory returns false with an
error detail and retries attachment on the next call. Permission failures raise
`BackendError` naming `kernel.yama.ptrace_scope`: run from an allowed parent or with
an appropriate ptrace policy/capability. The library changes no host policy.
