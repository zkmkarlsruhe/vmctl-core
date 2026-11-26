"""Raw-image cloning and self-contained process promotion, without qemu-img."""

import hashlib
import json
import os
import zipfile

import pytest

from vmctl_core import promotion
from vmctl_core.backends import BackendError, ProcessBackend, clone_process
from vmctl_core.catalog import BaseImage, Hardware


@pytest.fixture
def process_base(tmp_path):
    catalog = tmp_path / "catalog"
    (catalog / "images").mkdir(parents=True)
    (catalog / "images/system.img").write_bytes(b"golden system")
    (catalog / "images/data.img").write_bytes(b"golden data")
    (catalog / "images/system.img").chmod(0o444)
    media = tmp_path / "host.rom"
    media.write_bytes(b"pinned ROM")
    media.chmod(0o444)
    binary = tmp_path / "emulator"
    binary.write_text("#!/bin/sh\nexec sleep 60\n")
    binary.chmod(0o555)
    base = BaseImage(
        id="example",
        path="images/system.img",
        os="emulated",
        hw=Hardware(
            backend="process",
            process={
                "argv": ["./bin/emulator"],
                "images": ["images/data.img"],
                "media": {"roms/host.rom": str(media), "bin/emulator": str(binary)},
                "media_sha256": {
                    "roms/host.rom": hashlib.sha256(media.read_bytes()).hexdigest(),
                    "bin/emulator": hashlib.sha256(binary.read_bytes()).hexdigest(),
                },
                "env": {"WORK": "exhibit"},
                "alive_file": "alive",
                "alive_max_age_s": 10,
                "screen": "800x600x24",
            },
        ),
    )
    return base


def clone(base, tmp_path):
    return clone_process(
        base,
        catalog_dir=tmp_path / "catalog",
        domain_name="work",
        instance_dir=tmp_path / "instance",
        display_num=123,
        vnc_port=5999,
        spec_dir=tmp_path / "specs",
    )


def test_clone_copies_writable_goldens_and_links_pinned_media(process_base, tmp_path):
    primary, definition = clone(process_base, tmp_path)
    assert primary == tmp_path / "instance/images/system.img"
    assert primary.read_bytes() == b"golden system"
    assert primary.stat().st_mode & 0o200
    primary.write_bytes(b"changed")
    assert (tmp_path / "catalog/images/system.img").read_bytes() == b"golden system"
    assert (tmp_path / "instance/images/data.img").read_bytes() == b"golden data"
    assert (tmp_path / "instance/roms/host.rom").is_symlink()
    spec = ProcessBackend("work", instance_dir=tmp_path / "instance").spec
    assert spec.images == ["images/system.img", "images/data.img"]
    assert spec.virtual_display and spec.display == ":123" and spec.vnc_port == 5999
    assert spec.screen == "800x600x24"
    assert spec.env == {"WORK": "exhibit"}
    assert spec.alive_file == "alive" and spec.alive_max_age_s == 10
    assert definition == tmp_path / "specs/work.process.json"
    assert (tmp_path / "instance/process.json").read_bytes() == definition.read_bytes()


@pytest.mark.parametrize("digest", ["0" * 64, ""])
def test_clone_wrong_or_missing_pin_leaves_no_instance(process_base, tmp_path, digest):
    process_base.hw.process["media_sha256"]["roms/host.rom"] = digest
    with pytest.raises(BackendError, match=r"sha256 mismatch.*host\.rom"):
        clone(process_base, tmp_path)
    assert not (tmp_path / "instance").exists()
    assert not (tmp_path / "specs").exists()


def test_clone_copy_failure_leaves_no_instance(process_base, tmp_path, monkeypatch):
    def fail(*args):
        raise OSError("disk full")

    monkeypatch.setattr("vmctl_core.backends.process.shutil.copy2", fail)
    with pytest.raises(OSError, match="disk full"):
        clone(process_base, tmp_path)
    assert not (tmp_path / "instance").exists()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "process.json", "snapshots/x"])
def test_clone_rejects_unsafe_media_names(process_base, tmp_path, name):
    process_base.hw.process["media"][name] = str(tmp_path / "host.rom")
    with pytest.raises(BackendError, match="payload path"):
        clone(process_base, tmp_path)
    assert not (tmp_path / "instance").exists()


def test_process_bundle_roundtrip_without_qemu(process_base, tmp_path, monkeypatch):
    primary, _ = clone(process_base, tmp_path)
    primary.write_bytes(b"finished work")

    def no_command(*args, **kwargs):
        pytest.fail("process export must not invoke qemu-img or any subprocess")

    with monkeypatch.context() as patch:
        patch.setattr(promotion.subprocess, "run", no_command)
        bundle = promotion.create_process_bundle(
            tmp_path / "instance", tmp_path / "work-1.0", provenance={"source": "research"}
        )
        assert promotion.verify_bundle(bundle)["ok"]
        assert not bundle.stat().st_mode & 0o222
        assert not (bundle / "vm/images/system.img").stat().st_mode & 0o222
        assert not (bundle / "vm/roms/host.rom").is_symlink()
        manifest = promotion.read_yaml(bundle / "bundle.yaml")
        assert manifest["bundle_format"] == 1
        assert manifest["vm"]["backend"] == "process"
        assert promotion.read_yaml(bundle / "PROVENANCE.yaml") == {"source": "research"}
        exported = json.loads((bundle / "vm/process.json").read_text())
        assert exported["virtual_display"] is False
        assert exported["display"] == ":0"
        assert exported["media"]["roms/host.rom"] == "roms/host.rom"
        assert ProcessBackend("work", instance_dir=tmp_path / "instance").spec.virtual_display
        summary = promotion.pack_bundle_zip(bundle, tmp_path / "work.zip")
        assert summary["profile"] == "process" and not summary["baked"]
        unpacked = promotion.unpack_bundle_zip(tmp_path / "work.zip", tmp_path / "unpacked")
        assert promotion.verify_bundle(unpacked)["ok"]
        assert (unpacked / "vm/images/system.img").read_bytes() == b"finished work"
        assert (unpacked / "vm/bin/emulator").stat().st_mode & 0o111
        assert not list(unpacked.rglob("*.qcow2"))
        with pytest.raises(ValueError, match="do not need baking"):
            promotion.bake_disk(bundle, tmp_path / "unused.qcow2")
    # The copied binary and media remain usable after their host sources disappear.
    (tmp_path / "host.rom").unlink()
    (tmp_path / "emulator").unlink()
    b = ProcessBackend("exhibit", instance_dir=unpacked / "vm")
    try:
        b.start()
        assert b.is_running()
    finally:
        b.stop()
    promotion.unseal_bundle(bundle)
    (bundle / "vm/images/system.img").write_bytes(b"tampered")
    assert promotion.verify_bundle(bundle)["mismatched"] == ["vm/images/system.img"]
    with pytest.raises(ValueError, match="checksum verification"):
        promotion.pack_bundle_zip(bundle, tmp_path / "tampered.zip")


def test_unpack_checks_process_payload(process_base, tmp_path):
    clone(process_base, tmp_path)
    bundle = promotion.create_process_bundle(
        tmp_path / "instance", tmp_path / "bundle", provenance={}
    )
    promotion.pack_bundle_zip(bundle, tmp_path / "good.zip")
    with (
        zipfile.ZipFile(tmp_path / "good.zip") as source,
        zipfile.ZipFile(tmp_path / "bad.zip", "w") as dest,
    ):
        for name in source.namelist():
            data = b"tampered" if name.endswith("system.img") else source.read(name)
            dest.writestr(name, data)
    with pytest.raises(ValueError, match="checksum verification"):
        promotion.unpack_bundle_zip(tmp_path / "bad.zip", tmp_path / "unpacked")
    promotion.unseal_bundle(bundle)


def test_bundle_refuses_running_instance(process_base, tmp_path):
    _, definition = clone(process_base, tmp_path)
    spec = json.loads(definition.read_text())
    spec["virtual_display"] = False
    (tmp_path / "instance/process.json").write_text(json.dumps(spec))
    backend = ProcessBackend("work", instance_dir=tmp_path / "instance")
    backend.start()
    try:
        with pytest.raises(ValueError, match="stop the process"):
            promotion.create_process_bundle(
                tmp_path / "instance", tmp_path / "bundle", provenance={}
            )
        assert not (tmp_path / "bundle").exists()
    finally:
        backend.stop()


def test_bundle_rechecks_media_pin(process_base, tmp_path):
    clone(process_base, tmp_path)
    os.chmod(tmp_path / "host.rom", 0o644)
    (tmp_path / "host.rom").write_bytes(b"changed ROM")
    with pytest.raises(ValueError, match="media sha256 mismatch"):
        promotion.create_process_bundle(tmp_path / "instance", tmp_path / "bundle", provenance={})
    assert not (tmp_path / "bundle").exists()


def test_process_bundle_preserves_empty_working_directory(process_base, tmp_path):
    process_base.hw.process.update(cwd="runtime", argv=["sleep", "60"])
    clone(process_base, tmp_path)
    bundle = promotion.create_process_bundle(
        tmp_path / "instance", tmp_path / "bundle", provenance={}
    )
    try:
        promotion.pack_bundle_zip(bundle, tmp_path / "bundle.zip")
        unpacked = promotion.unpack_bundle_zip(tmp_path / "bundle.zip", tmp_path / "unpacked")
        assert (unpacked / "vm/runtime").is_dir()
        assert promotion.verify_bundle(unpacked)["ok"]
        backend = ProcessBackend("work", instance_dir=unpacked / "vm")
        try:
            backend.start()
            assert backend.is_running()
        finally:
            backend.stop()
    finally:
        promotion.unseal_bundle(bundle)
