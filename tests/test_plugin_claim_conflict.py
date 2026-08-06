"""Two plugins claiming the same backend_host must be flagged at bind time.

Before the check, an overlapping claim resolved silently by manifest-directory sort order —
an operator could ship two shims for the same host and never know which one wins. load_plugins
now logs a warning naming both plugins and the winner.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vmctl_core.plugins import PluginRegistry, load_plugins

_PLUGIN_PY = "def setup(registry):\n    pass\n"


def _write(root: Path, pid: str, backend_host: str | None) -> None:
    d = root / pid
    d.mkdir(parents=True, exist_ok=True)
    lines = [f"id: {pid}", f"name: {pid}", "entrypoint: plugin.py"]
    if backend_host:
        lines.append(f'backend_host: "{backend_host}"')
    (d / "manifest.yaml").write_text("\n".join(lines) + "\n")
    (d / "plugin.py").write_text(_PLUGIN_PY)


def test_conflict_is_warned(tmp_path, caplog):
    _write(tmp_path, "a-shim", "192.168.29.29")
    _write(tmp_path, "b-shim", "192.168.29.29")  # same host -> conflict
    reg = PluginRegistry()
    with caplog.at_level(logging.WARNING):
        load_plugins(tmp_path, reg)
    msgs = [r.getMessage() for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("claim conflict" in m and "192.168.29.29" in m for m in msgs), msgs


def test_distinct_hosts_no_warning(tmp_path, caplog):
    _write(tmp_path, "a-shim", "192.168.29.29")
    _write(tmp_path, "b-shim", "192.168.29.30")  # different host
    _write(tmp_path, "ui-only", None)  # no backend_host -> not a network shim
    reg = PluginRegistry()
    with caplog.at_level(logging.WARNING):
        load_plugins(tmp_path, reg)
    assert not any("claim conflict" in r.getMessage() for r in caplog.records)
