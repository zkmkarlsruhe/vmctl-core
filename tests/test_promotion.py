"""Promotion bundle format (research/29): checksums + verify, tamper detection."""

from vmctl_core import promotion


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
