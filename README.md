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

Consumed as a Poetry **path dependency** by sibling repos under `/x/coding/01-zkm/vmctl/`:

```toml
[tool.poetry.dependencies]
vmctl-core = { path = "../vmctl-core", develop = true }
```

MIT — see [`LICENSE`](LICENSE). © 2026 Marc Schütze @ ZKM | Center for Art and Media Karlsruhe.
A **ZKM Open-Source project**, part of the vmctl family, led by Marc Schütze as head researcher.
Generic modules adapted from `exhibition-vm-controller` (we own the copies here).
