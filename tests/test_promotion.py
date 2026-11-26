"""Promotion bundle format (research/29): checksums + verify, tamper detection."""

import os
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
    raw = cat_dir / "base.raw"
    with raw.open("wb") as f:
        f.write(b"A" * 65536)
        f.truncate(64 << 20)
    subprocess.run(
        ["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(raw), str(base)],
        check=True,
        capture_output=True,
    )
    raw.unlink()
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
    raw = root / "overlay.raw"
    with raw.open("wb") as f:
        f.write(b"A" * 65536)
        f.seek(1 << 20)
        f.write(b"B" * 65536)
        f.truncate(64 << 20)
    subprocess.run(
        [
            "qemu-img",
            "convert",
            "-f",
            "raw",
            "-O",
            "qcow2",
            "-B",
            str(base_path),
            "-F",
            "qcow2",
            str(raw),
            str(b / "vm" / "overlay.qcow2"),
        ],
        check=True,
        capture_output=True,
    )
    raw.unlink()
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
    assert summary["disk_sha256"] == promotion.sha256_file(root / "vm" / "disk.qcow2")
    subprocess.run(
        ["qemu-img", "compare", str(b / "vm" / "overlay.qcow2"), str(root / "vm" / "disk.qcow2")],
        check=True,
        capture_output=True,
    )
    assert promotion.verify_bundle(b)["ok"] is True
    repacked = promotion.pack_bundle_zip(root, tmp_path / "repacked.zip")
    assert repacked["baked"] is False
    assert repacked["disk_sha256"] == summary["disk_sha256"]


@_needs_qemu
def test_pack_thin_without_catalog_refuses(tmp_path):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    with pytest.raises(ValueError, match="catalog_path"):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip")


@_needs_qemu
def test_pack_base_sha_mismatch_refuses(tmp_path, monkeypatch):
    cat, _ = _golden(tmp_path / "catalog")
    # bundle claims a base sha that won't match the real golden
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", "0" * 64)

    def no_command(*args, **kwargs):
        pytest.fail("must reject a mismatched base sha256 before running qemu-img")

    monkeypatch.setattr(promotion.subprocess, "run", no_command)
    with pytest.raises(ValueError, match="sha256 mismatch"):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip", catalog_path=cat)


@_needs_qemu
@pytest.mark.parametrize("embedded", [False, True])
@pytest.mark.parametrize("digest", [None, "", "absent"])
def test_thin_main_requires_base_sha(tmp_path, monkeypatch, digest, embedded):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    if embedded:
        shutil.copy2(cat.parent / "winxp.qcow2", b / "vm" / "base.qcow2")
    ref_path = b / "vm" / "base.ref.yaml"
    ref = promotion.read_yaml(ref_path)
    ref["sha256"] = digest
    if digest == "absent":
        del ref["sha256"]
    promotion.write_yaml(ref_path, ref)
    promotion.write_checksums(b)

    def no_command(*args, **kwargs):
        pytest.fail("must reject a missing base sha256 before running qemu-img")

    monkeypatch.setattr(promotion.subprocess, "run", no_command)
    with pytest.raises(ValueError, match="missing golden base sha256"):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip", catalog_path=cat)
    with pytest.raises(ValueError, match="missing golden base sha256"):
        promotion.bake_disk(b, tmp_path / "disk.qcow2", catalog_path=cat)


@_needs_qemu
@pytest.mark.parametrize("bad_disk", [0, 1])
@pytest.mark.parametrize("digest", [None, "", "absent", "0" * 64])
def test_every_aux_requires_matching_base_sha(tmp_path, monkeypatch, bad_disk, digest):
    cat, base_sha = _golden(tmp_path / "catalog")
    base = cat.parent / "winxp.qcow2"
    b = _mk_thin_vm_bundle(tmp_path / "drive", base, base_sha)
    by = promotion.read_yaml(b / promotion.BUNDLE_YAML)
    aux = []
    for index in range(2):
        rel = f"vm/aux-{index}.qcow2"
        shutil.copy2(b / "vm" / "overlay.qcow2", b / rel)
        aux.append({"overlay": rel, "base_path": str(base), "base_sha": base_sha})
    aux[bad_disk]["base_sha"] = digest
    if digest == "absent":
        del aux[bad_disk]["base_sha"]
    by["vm"]["aux_disks"] = aux
    promotion.write_yaml(b / promotion.BUNDLE_YAML, by)
    promotion.write_checksums(b)

    def no_command(*args, **kwargs):
        pytest.fail("must reject an invalid aux base sha256 before running qemu-img")

    monkeypatch.setattr(promotion.subprocess, "run", no_command)
    error = "aux base sha256 mismatch" if digest == "0" * 64 else "missing aux base sha256"
    with pytest.raises(ValueError, match=error):
        promotion.pack_bundle_zip(b, tmp_path / "x.zip", catalog_path=cat)


@_needs_qemu
def test_bake_rejects_wrong_flat_content(tmp_path, monkeypatch):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    run = subprocess.run

    def corrupt_conversion(cmd, **kwargs):
        result = run(cmd, **kwargs)
        if cmd[1] == "convert":
            # A valid but empty image must fail the real content comparison.
            run(
                ["qemu-img", "create", "-f", "qcow2", cmd[-1], "64M"],
                check=True,
                capture_output=True,
            )
        return result

    monkeypatch.setattr(promotion.subprocess, "run", corrupt_conversion)
    with pytest.raises(RuntimeError, match=r"qemu-img compare failed:.*Content mismatch"):
        promotion.pack_bundle_zip(b, tmp_path / "bad.zip", catalog_path=cat)
    assert not (tmp_path / "bad.zip").exists()
    assert promotion.verify_bundle(b)["ok"] is True


@_needs_qemu
def test_bake_uses_recorded_base_after_relocation(tmp_path):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    expected = tmp_path / "expected.qcow2"
    subprocess.run(
        ["qemu-img", "convert", "-O", "qcow2", str(b / "vm" / "overlay.qcow2"), str(expected)],
        check=True,
        capture_output=True,
    )
    relocated = tmp_path / "relocated"
    cat.parent.rename(relocated)
    disk = tmp_path / "flat.qcow2"
    digest = promotion.bake_disk(b, disk, catalog_path=relocated / cat.name)
    assert digest == promotion.sha256_file(disk)
    subprocess.run(
        ["qemu-img", "compare", str(expected), str(disk)], check=True, capture_output=True
    )
    assert promotion.verify_bundle(b)["ok"] is True


@_needs_qemu
def test_pack_fat_bundle_without_catalog(tmp_path):
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    shutil.copy2(cat.parent / "winxp.qcow2", b / "vm" / "base.qcow2")
    (b / "vm" / "base.ref.yaml").unlink()
    by = promotion.read_yaml(b / promotion.BUNDLE_YAML)
    by["vm"]["profile"] = "fat"
    by["vm"]["base"]["included"] = True
    promotion.write_yaml(b / promotion.BUNDLE_YAML, by)
    promotion.write_checksums(b)
    summary = promotion.pack_bundle_zip(b, tmp_path / "fat.zip")
    assert summary["baked"] is True and summary["profile"] == "baked"
    unpacked = promotion.unpack_bundle_zip(tmp_path / "fat.zip", tmp_path / "import")
    assert summary["disk_sha256"] == promotion.sha256_file(unpacked / "vm" / "disk.qcow2")


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
    assert [d["sha256"] for d in m["disks"]] == s["disk_sha256s"]
    assert [promotion.sha256_file(root / d["path"]) for d in m["disks"]] == s["disk_sha256s"]
    for source, disk in zip(["aux-0.qcow2", "overlay.qcow2"], m["disks"], strict=True):
        subprocess.run(
            ["qemu-img", "compare", str(b / "vm" / source), str(root / disk["path"])],
            check=True,
            capture_output=True,
        )
    repacked = promotion.pack_bundle_zip(root, tmp_path / "repacked-multi.zip")
    assert repacked["profile"] == "baked-multi" and repacked["baked"] is False
    again = promotion.unpack_bundle_zip(tmp_path / "repacked-multi.zip", tmp_path / "again")
    assert promotion.read_yaml(again / promotion.BUNDLE_YAML)["vm"] == m


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


def test_symlink_in_bundle_is_unsafe_and_never_chmoded(tmp_path):
    """A member-made symlink must not be hashed, packed, or have its TARGET chmod'ed by seal."""
    target = tmp_path / "id_ed25519"
    target.write_text("secret")
    target.chmod(0o600)
    b = _mk_bundle(tmp_path)
    (b / "plugin" / "x").symlink_to(target)

    assert not any(r.as_posix() == "plugin/x" for r in promotion.iter_bundle_files(b))
    v = promotion.verify_bundle(b)
    assert v["ok"] is False and v["unsafe"] == ["plugin/x"]
    promotion.seal_bundle(b)
    assert target.stat().st_mode & 0o777 == 0o600
    promotion.remove_sealed_tree(b)
    assert target.stat().st_mode & 0o777 == 0o600 and not b.exists()


def test_bake_surfaces_qemu_img_stderr(tmp_path, monkeypatch):
    overlay = tmp_path / "overlay.qcow2"
    overlay.write_bytes(b"x")

    def boom(cmd, **kw):
        raise subprocess.CalledProcessError(1, cmd, stderr=b"qemu-img: No space left on device")

    monkeypatch.setattr(promotion.subprocess, "run", boom)
    with pytest.raises(RuntimeError, match=r"qemu-img rebase failed: .*No space left"):
        promotion._bake_one(overlay, tmp_path / "base.qcow2", tmp_path / "out.qcow2", "qemu-img")


# --- sealing: a promoted bundle should not be modifiable in place --------------

#: The seal is unix modes, and root ignores unix modes. CI runs as root inside its container, so
#: the "writing fails" half of these tests is only meaningful for an unprivileged user; the modes
#: themselves are asserted either way. This is the same limit the seal has in production: it stops
#: the ordinary accident, not a process that is already root on the host.
_IS_ROOT = os.geteuid() == 0
_needs_unprivileged = pytest.mark.skipif(_IS_ROOT, reason="root bypasses file permissions")


def _modes(bundle):
    """(file modes, dir modes) actually on disk, as sets of permission bits."""
    files = {p.stat().st_mode & 0o777 for p in bundle.rglob("*") if p.is_file()}
    dirs = {p.stat().st_mode & 0o777 for p in [bundle, *bundle.rglob("*")] if p.is_dir()}
    return files, dirs


def test_seal_marks_every_file_and_directory_read_only(tmp_path):
    b = _mk_bundle(tmp_path)
    files, dirs = _modes(b)
    promotion.seal_bundle(b)
    files, dirs = _modes(b)
    assert files == {0o444}, f"a writable file survived the seal: {files}"
    assert dirs == {0o555}, f"a writable directory survived the seal: {dirs}"


@_needs_unprivileged
def test_sealed_bundle_refuses_writes_and_new_files(tmp_path):
    """The point of the seal is that the ordinary ways a bundle rots — an overwrite, a stray file
    dropped beside the payload, a delete — fail at the moment they happen instead of surfacing
    years later as a checksum mismatch on an exhibition machine."""
    b = _mk_bundle(tmp_path)
    promotion.seal_bundle(b)

    with pytest.raises(PermissionError):
        (b / "plugin" / "plugin.py").write_text("tampered\n")
    with pytest.raises(PermissionError):
        (b / "plugin" / "extra.py").write_text("added later\n")
    with pytest.raises(PermissionError):
        (b / "plugin" / "manifest.yaml").unlink()

    # ...and the bundle still verifies, because nothing got through.
    assert promotion.verify_bundle(b)["ok"] is True


def test_sealed_bundle_is_still_readable_and_verifiable(tmp_path):
    """Sealing must not break the two things that happen to a bundle for the rest of its life:
    reading it, and re-hashing it."""
    b = _mk_bundle(tmp_path)
    promotion.seal_bundle(b)
    assert (b / "plugin" / "plugin.py").read_text() == "def setup(registry): pass\n"
    assert promotion.verify_bundle(b)["ok"] is True


def test_unseal_restores_write_access_so_a_bundle_can_be_superseded(tmp_path):
    """A re-export supersedes the previous bundle with shutil.rmtree, which cannot remove entries
    from a read-only directory. Without unseal, sealing would make re-promoting impossible."""
    b = _mk_bundle(tmp_path)
    promotion.seal_bundle(b)
    if not _IS_ROOT:
        with pytest.raises(OSError):
            shutil.rmtree(b)
    promotion.unseal_bundle(b)
    files, dirs = _modes(b)
    assert files == {0o644} and dirs == {0o755}
    shutil.rmtree(b)
    assert not b.exists()


def test_sealing_is_idempotent(tmp_path):
    b = _mk_bundle(tmp_path)
    assert promotion.seal_bundle(b) == promotion.seal_bundle(b)
    promotion.unseal_bundle(b)
    (b / "plugin" / "plugin.py").write_text("edited\n")  # no exception


def test_remove_sealed_tree_deletes_a_drive_holding_a_sealed_bundle(tmp_path):
    """Purging a project must take its promoted bundles with it. Plain rmtree cannot: it fails to
    unlink entries out of the bundle's read-only directories and leaves the drive half-deleted."""
    drive = tmp_path / "proj"
    (drive / "work").mkdir(parents=True)
    (drive / "work" / "notes.md").write_text("scratch\n")
    bundle = _mk_bundle(drive / "exhibition")
    promotion.seal_bundle(bundle)

    if not _IS_ROOT:
        with pytest.raises(OSError):
            shutil.rmtree(drive)
        assert drive.exists(), "precondition: plain rmtree should have failed here"

    promotion.remove_sealed_tree(drive)
    assert not drive.exists()


def test_remove_sealed_tree_still_deletes_an_ordinary_tree(tmp_path):
    plain = tmp_path / "nothing-sealed"
    (plain / "a").mkdir(parents=True)
    (plain / "a" / "f.txt").write_text("x\n")
    promotion.remove_sealed_tree(plain)
    assert not plain.exists()


def test_a_sealed_bundle_packs_and_unpacks_writable(tmp_path):
    """The seal must not follow the bundle onto an exhibition machine.

    Two things have to hold for the handoff to survive sealing. Packing must work FROM a read-only
    bundle — the catalog serves zips off the drive rvmc promoted into, so it never has write access
    to what it is packing. And the unpacked install must be WRITABLE: a qcow2 restored at 0444 is
    an exhibit whose VM cannot boot. Python's zipfile does not restore permission bits on extract,
    which is what makes this work — pinned here because it is load-bearing and easy to break by
    "improving" the extractor to preserve modes."""
    b = _mk_bundle(tmp_path)
    promotion.seal_bundle(b)

    z = tmp_path / "sample.zip"
    promotion.pack_bundle_zip(b, z)  # must not need write access to b
    assert z.is_file()

    out = promotion.unpack_bundle_zip(z, tmp_path / "installed")
    assert promotion.verify_bundle(out)["ok"] is True
    for p in out.rglob("*"):
        if p.is_file():
            mode = p.stat().st_mode & 0o777
            assert mode & 0o200, f"{p.relative_to(out)} unpacked read-only ({mode:o})"


@_needs_qemu
def test_pack_bakes_a_SEALED_vm_bundle(tmp_path):
    """The catalog bakes zips straight off the drive rvmc promoted into, so the bundle it reads
    is always sealed. Baking copies the overlay to scratch and rebases it — and shutil.copy2
    carries the source's 0444 along, so `qemu-img rebase` fails on the copy. Found by baking a
    real 474 MB win2000 bundle on the lab box, not by the plugin-only sealing tests, which never
    reach a disk."""
    cat, base_sha = _golden(tmp_path / "catalog")
    b = _mk_thin_vm_bundle(tmp_path / "drive", cat.parent / "winxp.qcow2", base_sha)
    promotion.seal_bundle(b)

    out = tmp_path / "artwork.zip"
    summary = promotion.pack_bundle_zip(b, out, catalog_path=cat)
    assert summary["baked"] is True

    root = promotion.unpack_bundle_zip(out, tmp_path / "import")
    assert promotion.verify_bundle(root)["ok"] is True
    assert (root / "vm" / "disk.qcow2").stat().st_mode & 0o200, "installed disk must be writable"
    # and the source bundle is still sealed — baking reads, it does not unseal
    files = {p.stat().st_mode & 0o777 for p in b.rglob("*") if p.is_file()}
    assert files == {0o444}, files
