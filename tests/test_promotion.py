"""Promotion bundle format (research/29): checksums + verify, tamper detection."""

import shutil
import subprocess

import pytest

from vmctl_core import promotion

_HAS_QEMU = shutil.which("qemu-img") is not None
_needs_qemu = pytest.mark.skipif(not _HAS_QEMU, reason="qemu-img not installed")


def _mk_bundle(root):
    b = root / "sample-work-1.0.0"
    (b / "plugin").mkdir(parents=True)
    (b / "plugin" / "manifest.yaml").write_text("id: sample-work\nversion: 1.0.0\n")
    (b / "plugin" / "plugin.py").write_text("def setup(registry): pass\n")
    promotion.write_yaml(
        b / promotion.BUNDLE_YAML,
        {
            "bundle_format": promotion.BUNDLE_FORMAT,
            "plugin": {"id": "sample-work", "version": "1.0.0"},
        },
    )
    promotion.write_checksums(b)
    return b


def test_verify_ok_roundtrip(tmp_path):
    b = _mk_bundle(tmp_path)
    v = promotion.verify_bundle(b)
    assert v["ok"] is True
    assert v["format"] == promotion.BUNDLE_FORMAT
    assert v["files"] == 3  # bundle.yaml + 2 plugin files


def test_verify_detects_tamper_missing_extra(tmp_path):
    b = _mk_bundle(tmp_path)
    (b / "plugin" / "plugin.py").write_text("def setup(registry): EVIL\n")
    v = promotion.verify_bundle(b)
    assert v["ok"] is False and v["mismatched"] == ["plugin/plugin.py"]

    b2 = _mk_bundle(tmp_path / "two")
    (b2 / "plugin" / "manifest.yaml").unlink()
    assert promotion.verify_bundle(b2)["missing"] == ["plugin/manifest.yaml"]

    b3 = _mk_bundle(tmp_path / "three")
    (b3 / "smuggled.bin").write_bytes(b"x")
    assert promotion.verify_bundle(b3)["extra"] == ["smuggled.bin"]


def test_verify_non_bundle(tmp_path):
    v = promotion.verify_bundle(tmp_path)
    assert v["ok"] is False and "not a bundle" in v["error"]


def test_nested_checksums_file_is_hashed_and_verified(tmp_path):
    # FIX 1: a file that merely shares the manifest's name deeper in the tree
    # (plugin/CHECKSUMS.sha256) is real payload — it MUST be hashed/verified, not
    # silently skipped (which used to leave it tamperable while verify said ok).
    b = _mk_bundle(tmp_path)
    nested = b / "plugin" / promotion.CHECKSUMS
    nested.write_text("deadbeef  plugin/manifest.yaml\n")
    promotion.write_checksums(b)

    rels = {rel.as_posix() for rel in promotion.iter_bundle_files(b)}
    assert "plugin/CHECKSUMS.sha256" in rels  # included, not excluded
    assert promotion.verify_bundle(b)["ok"] is True  # clean bundle still verifies

    nested.write_text("tampered\n")  # now flip one byte
    v = promotion.verify_bundle(b)
    assert v["ok"] is False
    assert "plugin/CHECKSUMS.sha256" in v["mismatched"]


def _golden(cat_dir):
    """A real qcow2 golden in a catalog dir; returns (catalog.yaml, sha256)."""
    cat_dir.mkdir(parents=True)
    base = cat_dir / "winxp.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(base), "64M"], check=True, capture_output=True
    )
    (cat_dir / "catalog.yaml").write_text(
        "bases:\n  - id: winxp-golden\n    path: winxp.qcow2\n    os: windows-xp\n"
    )
    return cat_dir / "catalog.yaml", promotion.sha256_file(base)


def _mk_thin_vm_bundle(root, base_path, base_sha):
    """A thin bundle: a real overlay backed by base + base ref — the drive default."""
    b = root / "sample-work-1.0.0"
    (b / "plugin").mkdir(parents=True)
    (b / "plugin" / "manifest.yaml").write_text("id: sample-work\nversion: 1.0.0\n")
    (b / "vm").mkdir()
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            str(base_path),
            "-F",
            "qcow2",
            str(b / "vm" / "overlay.qcow2"),
        ],
        check=True,
        capture_output=True,
    )
    (b / "vm" / "domain.template.xml").write_text("<domain/>\n")
    promotion.write_yaml(
        b / "vm" / "base.ref.yaml",
        {
            "id": "winxp-golden",
            "name": "WinXP",
            "path": "winxp.qcow2",
            "os": "windows-xp",
            "sha256": base_sha,
        },
    )
    promotion.write_yaml(
        b / promotion.BUNDLE_YAML,
        {
            "bundle_format": promotion.BUNDLE_FORMAT,
            "plugin": {"id": "sample-work", "version": "1.0.0"},
            "vm": {
                "profile": "thin",
                "base": {"id": "winxp-golden", "included": False},
                "artifact": {
                    "kind": "overlay",
                    "path": "vm/overlay.qcow2",
                    "ready_snapshot": "ready",
                },
            },
        },
    )
    promotion.write_checksums(b)
    return b


@_needs_qemu
def test_pack_bakes_thin_bundle_into_standalone_disk(tmp_path):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)

    out = tmp_path / "artwork.zip"
    summary = promotion.pack_bundle_zip(b, out, catalog_path=cat)
    assert summary["baked"] is True and summary["profile"] == "baked"

    # source bundle stays thin/untouched
    assert (b / "vm" / "overlay.qcow2").exists()
    assert not (b / "vm" / "disk.qcow2").exists()

    root = promotion.unpack_bundle_zip(out, tmp_path / "import")
    # only the baked disk travels — no golden, no overlay, no base ref
    assert (root / "vm" / "disk.qcow2").is_file()
    assert not (root / "vm" / "base.qcow2").exists()
    assert not (root / "vm" / "overlay.qcow2").exists()
    assert not (root / "vm" / "base.ref.yaml").exists()

    # the baked disk is standalone (no backing file)
    info = subprocess.run(
        ["qemu-img", "info", str(root / "vm" / "disk.qcow2")],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert "backing file" not in info

    v = promotion.verify_bundle(root)
    assert v["ok"] is True, v
    by = promotion.read_yaml(root / promotion.BUNDLE_YAML)
    assert by["vm"]["profile"] == "baked"
    assert by["vm"]["artifact"]["kind"] == "disk"
    assert by["vm"]["artifact"]["ready_snapshot"] == "ready"
    assert by["vm"]["artifact"]["sha256"] == summary["disk_sha256"]


@_needs_qemu
def test_pack_thin_without_catalog_refuses(tmp_path):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    with pytest.raises(ValueError, match="catalog_path"):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip")


@_needs_qemu
def test_pack_base_sha_mismatch_refuses(tmp_path):
    cat, _ = _golden(tmp_path / "catalog")
    # bundle claims a base sha that won't match the real golden
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", "wrong-sha")
    with pytest.raises(ValueError, match="sha256 mismatch"):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip", catalog_path=cat)


@_needs_qemu
def test_pack_baked_multi_flattens_aux_and_main(tmp_path):
    # a macOS-style thin bundle: an OpenCore aux disk + the main disk
    cat, main_sha = _golden(tmp_path / "catalog")
    oc = cat.parent / "opencore.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(oc), "16M"], check=True, capture_output=True
    )
    oc_sha = promotion.sha256_file(oc)

    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", main_sha)
    subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            str(oc),
            "-F",
            "qcow2",
            str(b / "vm" / "aux-0.qcow2"),
        ],
        check=True,
        capture_output=True,
    )
    by = promotion.read_yaml(b / promotion.BUNDLE_YAML)
    by["vm"]["aux_disks"] = [
        {
            "overlay": "vm/aux-0.qcow2",
            "base_path": str(oc),
            "base_sha": oc_sha,
            "bus": "sata",
            "boot": 1,
        }
    ]
    by["vm"]["host_requires"] = ["/usr/share/ovmf/OVMF.fd"]
    promotion.write_yaml(b / promotion.BUNDLE_YAML, by)
    promotion.write_checksums(b)

    out = tmp_path / "multi.zip"
    s = promotion.pack_bundle_zip(b, out, catalog_path=cat)
    assert s["profile"] == "baked-multi" and len(s["disk_sha256s"]) == 2

    root = promotion.unpack_bundle_zip(out, tmp_path / "imp")
    # aux-first ordering; overlays + base ref dropped
    assert (root / "vm" / "disk-0.qcow2").is_file() and (root / "vm" / "disk-1.qcow2").is_file()
    assert not (root / "vm" / "overlay.qcow2").exists()
    assert not (root / "vm" / "aux-0.qcow2").exists()
    assert not (root / "vm" / "base.ref.yaml").exists()
    assert promotion.verify_bundle(root)["ok"] is True
    m = promotion.read_yaml(root / promotion.BUNDLE_YAML)["vm"]
    assert m["profile"] == "baked-multi"
    assert [d["role"] for d in m["disks"]] == ["aux", "main"]
    assert m["host_requires"] == ["/usr/share/ovmf/OVMF.fd"]


def test_unpack_rejects_zip_slip(tmp_path):
    import zipfile

    import pytest

    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(evil, "w") as z:
        z.writestr("../escape.txt", "pwned")
    with pytest.raises(ValueError, match="unsafe path"):
        promotion.unpack_bundle_zip(evil, tmp_path / "out")


def test_pack_plugin_only_bundle_roundtrips(tmp_path):
    b = _mk_bundle(tmp_path)  # no vm/ section
    out = tmp_path / "plugin-only.zip"
    summary = promotion.pack_bundle_zip(b, out)  # no catalog needed
    assert summary["baked"] is False and summary["profile"] == "plugin-only"
    root = promotion.unpack_bundle_zip(out, tmp_path / "imp")
    assert promotion.verify_bundle(root)["ok"] is True


def test_verify_rejects_path_escaping_root(tmp_path):
    # FIX 2: a hand-edited entry pointing outside the bundle must fail verification
    # and never read the arbitrary host file it names.
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"secret host file")
    b = _mk_bundle(tmp_path)
    cs = b / promotion.CHECKSUMS
    cs.write_text(cs.read_text() + f"{promotion.sha256_file(outside)}  ../outside.bin\n")

    v = promotion.verify_bundle(b)
    assert v["ok"] is False
    assert "../outside.bin" in v["unsafe"]
    assert "outside" in v["error"]
