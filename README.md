# vmctl Core

[![ZKM](https://img.shields.io/badge/ZKM-Karlsruhe-blue)](https://zkm.de)
[![ZKM Open Source](https://img.shields.io/badge/ZKM-Open%20Source-blue)](https://github.com/zkmkarlsruhe)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

> **Made with and by AI.** The code, tests and documentation were written by AI agents. Verified by automated tests, a CI merge gate and a conservator in the loop. [How this was made](https://vmctl.org/how-this-was-made/)

The shared foundation library for the vmctl born-digital-art conservation platform, developed at
**ZKM | Center for Art and Media Karlsruhe**.

## Overview

Shared foundation for ZKM's VM-conservation controllers. Provides:

- **Pluggable VM backend** (`backends/`) — one `VMBackend` Protocol; the catalog's `hw.backend`
  selects one of five implementations (`backends/registry.py`):
  - `libvirt` — libvirt (`qemu:///system`), including the qemu-system-ppc Mac OS 9 tier.
  - `q800` — qemu-system-m68k `-M q800` as a process with QMP + VNC.
  - `sheepshaver` — SheepShaver (classic Mac PPC) SDL2 emulator in an Xvfb + x11vnc process group.
  - `basilisk2` — Basilisk II (classic Mac 68k) SDL2 emulator in an Xvfb + x11vnc process group.
  - `process` — any emulator run from one command line (e.g. MAME, FS-UAE), defined by `process.json`.
- **Shared plugin spec + runtime** (`plugins/`) — the contract a plugin conforms to; a plugin
  built and tested in the **research** controller promotes unchanged to the **exhibition** controller.
- Snapshot helpers, screen capture, guest I/O (QEMU guest agent).

**Dependency rule:** apps depend on core; core never imports an app. This keeps the exhibition
(show) controller runnable **without** the research controller.

Consumed as a Poetry **path dependency** by sibling repos under `<workspace>/vmctl/`:

```toml
[tool.poetry.dependencies]
vmctl-core = { path = "../vmctl-core", develop = true }
```

MIT — see [`LICENSE`](LICENSE). © 2026 Marc Schütze @ ZKM | Center for Art and Media Karlsruhe.
A **ZKM Open-Source project**, part of the vmctl family, led by Marc Schütze as head researcher.
Generic modules adapted from `exhibition-vm-controller` (we own the copies here).

## Made with and by AI

**The code, the tests and the documentation in this repository were written by AI agents, directed
by one conservator at ZKM.** Not assisted, not autocompleted. The full statement is at
[vmctl.org/how-this-was-made](https://vmctl.org/how-this-was-made/).

**How it is verified.**

- **Automated tests.** Every change runs the test suite in CI, on synthetic bytes rather than lucky
  fixtures.
- **A CI merge gate.** A change reaches `main` only when its full pipeline is green.
- **A conservator in the loop.** A conservator sets every task, checks the results against real
  artworks and decides what ships.
- **Evidence, not assertions.** Facts are extracted deterministically and carry their evidence.
  Coverage is reported honestly, including where a walk only got halfway. Formats we
  reverse-engineer are written down, so a finding can be re-derived by someone who does not trust
  us.

**Why.** Media-art conservation has an enormous surface and a tiny workforce: every work is a
different decade, a different runtime, a different undocumented format. Covering that by hand, at
the pace works are decaying, is not something a one-person team does. The comparison is not
"AI-written tool vs. hand-written tool". It is "this tool vs. no tool", while the disks keep
failing.

**Limits.** Generated code still carries generated blind spots, so anything these tools assert
about an artwork is a starting point for a conservator, never a verdict.
