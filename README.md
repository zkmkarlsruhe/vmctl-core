# vmctl Core

[![ZKM](https://img.shields.io/badge/ZKM-Karlsruhe-blue)](https://zkm.de)
[![ZKM Open Source](https://img.shields.io/badge/ZKM-Open%20Source-blue)](https://github.com/zkmkarlsruhe)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

The shared foundation library for the vmctl born-digital-art conservation platform, developed at
**ZKM | Center for Art and Media Karlsruhe**.

## Overview

Shared foundation for ZKM's VM-conservation controllers. Provides:

- **Pluggable VM backend** (`backends/`) — one `VMBackend` Protocol, implementations for
  libvirt (`qemu:///system`) now and `qemu-direct` (QMP) later.
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

## How this software was written: AI vibe-coded, on purpose

**This codebase was written by AI agents, directed by one conservator at ZKM.** Not assisted, not
autocompleted — the code, the tests and most of the documentation were produced by agents working
from prompts and reviewed by a human.

**Why.** Media-art conservation has an enormous surface and a tiny workforce: every work is a
different decade, a different runtime, a different undocumented format. Covering that by hand, at
the pace works are decaying, is not something a one-person team does. The honest comparison is not
"AI-written tool vs. hand-written tool" — it is "this tool vs. no tool", while the disks keep
failing.

**What we do about the risk.** Facts are extracted deterministically and carry their evidence;
coverage is reported honestly, including where a walk only got halfway; tests run on synthetic
bytes rather than lucky fixtures; formats we reverse-engineer are written down so a finding can be
re-derived by someone who does not trust us. Generated code still carries generated blind spots —
so anything these tools assert about an artwork is a starting point for a conservator, never a
verdict.
