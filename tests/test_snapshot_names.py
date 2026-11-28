"""Invalid snapshot names must fail before touching files or invoking a backend tool."""

from pathlib import Path

import pytest
from test_agent_probe_gate import NO_CHANNEL, _backend
from test_mac_emu import _sheep
from test_process_backend import make
from test_qemu_q800 import _defined, _fake_qemu_img

from vmctl_core.backends import BackendError


@pytest.fixture(params=["", "../x", "a/b", "/abs", "-x", "--option", ".", "..", ".x.staging"])
def invalid_name(request, tmp_path):
    return str(tmp_path / "abs") if request.param == "/abs" else request.param


def _reject_all(backend, name):
    for operation in (backend.snapshot_create, backend.snapshot_revert, backend.snapshot_delete):
        with pytest.raises(BackendError, match="invalid snapshot name"):
            operation(name)


def _contents(root):
    return {p: p.read_bytes() if p.is_file() else None for p in root.rglob("*")}


def test_process_snapshot_name(tmp_path, invalid_name):
    backend = make(tmp_path)
    (tmp_path / "x").mkdir()
    (tmp_path / "x/keep").write_bytes(b"keep")
    before = _contents(tmp_path)
    _reject_all(backend, invalid_name)
    assert _contents(tmp_path) == before


def test_mac_snapshot_name(tmp_path, invalid_name):
    backend = _sheep(tmp_path)
    Path(backend.disk).write_bytes(b"current")
    backend.snapshots_dir.mkdir(parents=True)
    (backend.instance_dir / "x.dsk").write_bytes(b"keep")
    (backend.instance_dir / "x.nvram").write_bytes(b"keep pram")
    before = _contents(tmp_path)
    _reject_all(backend, invalid_name)
    assert _contents(tmp_path) == before


def test_libvirt_snapshot_name(invalid_name, monkeypatch):
    backend, calls = _backend(NO_CHANNEL)
    monkeypatch.setattr(backend, "_flush_conntrack", lambda: pytest.fail("unexpected revert"))
    _reject_all(backend, invalid_name)
    assert calls == []


@pytest.mark.parametrize("hmp_unsafe", ["x y", "x\n", "x" * 65, "café"])
def test_q800_rejects_non_hmp_token(tmp_path, hmp_unsafe):
    backend = _defined(tmp_path)
    backend.agent_seen_path.touch()
    _reject_all(backend, hmp_unsafe)


@pytest.mark.parametrize("name", ["vor Installation", "café"])
def test_free_text_names_stay_valid_outside_q800(tmp_path, name):
    from vmctl_core.backends.base import checked_snapshot_name

    assert checked_snapshot_name(name) == name


def test_q800_snapshot_name(tmp_path, invalid_name):
    backend = _defined(tmp_path)
    tool, _ = _fake_qemu_img(tmp_path, "0 B")
    backend.settings.qemu_img_bin = str(tool)
    backend.agent_seen_path.touch()
    before = _contents(tmp_path)
    _reject_all(backend, invalid_name)
    assert _contents(tmp_path) == before
