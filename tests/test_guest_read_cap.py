"""guest_read_file must fail closed when the guest sends more than the cap,
and clone_base must reject a traversal domain_name regardless of caller validation."""

import base64
from types import SimpleNamespace

import pytest

from vmctl_core import clone
from vmctl_core.backends.base import BackendError
from vmctl_core.backends.libvirt_backend import MAX_GUEST_READ_BYTES, LibvirtBackend


def test_guest_read_file_caps_guest_controlled_size():
    be = LibvirtBackend.__new__(LibvirtBackend)
    chunk_b64 = base64.b64encode(b"\0" * 65536).decode()
    calls = {"n": 0}

    def fake_agent(cmd):
        if cmd["execute"] == "guest-file-open":
            return 1
        if cmd["execute"] == "guest-file-read":
            calls["n"] += 1
            return {"buf-b64": chunk_b64, "eof": False}  # a guest that never stops
        return {}

    be._agent = fake_agent
    with pytest.raises(BackendError, match="guest-read cap"):
        be.guest_read_file("/huge")
    # bounded: the loop stopped just past the cap, not at some arbitrary later point
    assert calls["n"] <= MAX_GUEST_READ_BYTES // 65536 + 1


def test_guest_read_file_under_cap_passes_through():
    be = LibvirtBackend.__new__(LibvirtBackend)
    payload = b"hello"

    def fake_agent(cmd):
        if cmd["execute"] == "guest-file-open":
            return 1
        if cmd["execute"] == "guest-file-read":
            return {"buf-b64": base64.b64encode(payload).decode(), "eof": True}
        return {}

    be._agent = fake_agent
    assert be.guest_read_file("/small") == payload


def test_clone_base_rejects_traversal_domain(tmp_path):
    dummy = SimpleNamespace(hw=SimpleNamespace(arch="x86_64", blank_disk_gb=0))
    with pytest.raises(ValueError, match="domain_name"):
        clone.clone_base(
            dummy,  # type: ignore[arg-type]  # never reached past validation
            catalog_dir=tmp_path,
            domain_name="../escape",
            overlays_dir=tmp_path,
            xml_dir=tmp_path,
        )
    assert not (tmp_path.parent / "escape.qcow2").exists()
