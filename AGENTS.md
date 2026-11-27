# AGENTS.md: vmctl-core

Engineering rules for all vmctl repos: https://docs.vmctl.org/contributing/engineering/
(source: `vmctl-docs/contributing/engineering.md`). They apply here in full: size limits,
structure, code style, tests, workflow. This file adds only what is specific to this repo.

Shared library (backends, capture, promotion) plus emulator images. Consumed by rvmc and autopsy as a path dependency.

## Gate

Run before every push. These are the commands of the CI `check` job; the pipeline is the authority.

```sh
poetry check --lock
poetry install --no-interaction
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy vmctl_core
poetry run pytest
python3 scripts/check_sizes.py
```

## Repo specifics

- This is the home for logic shared by more than one repo. Before duplicating code in rvmc or autopsy, move it here.
- A change to a public name here breaks consumers: grep `research-vm-controller` and `artwork-autopsy` for every caller and fix them in the same change set.
- Emulator images: bump `emulators/<emu>/VERSION` for any change under that directory.
- `backends/qemu_q800.py` and `capture.py` are baselined over the limits; extract before adding.
