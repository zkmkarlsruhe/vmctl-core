"""A bundle may only name paths inside itself (2026-09-08 sweep).

CHECKSUMS.sha256 is not a signature — whoever writes the bundle writes the checksums too — so
verification proves the payload matches the manifest, never that the manifest is honest. The
paths bundle.yaml declares for its own disks were joined to the bundle root and used directly.
"""

import zipfile

import pytest

from vmctl_core.promotion import unpack_bundle_zip


def test_a_declared_path_may_not_leave_the_bundle(tmp_path):
    from vmctl_core.promotion import bundle_path  # new helper: imported here so this file
    # still COLLECTS against the pre-fix module and the behavioural tests below can run

    root = tmp_path / "work-1.0"
    (root / "vm").mkdir(parents=True)
    (root / "vm" / "overlay.qcow2").write_bytes(b"x")
    assert bundle_path(root, "vm/overlay.qcow2").is_file()

    victim = tmp_path / "other-project" / "vm"
    victim.mkdir(parents=True)
    (victim / "overlay.qcow2").write_bytes(b"secret")

    for escape in (
        "../other-project/vm/overlay.qcow2",
        "vm/../../other-project/vm/overlay.qcow2",
        "/etc/passwd",
    ):
        with pytest.raises(ValueError, match="outside itself"):
            bundle_path(root, escape)


def test_bake_refuses_a_bundle_that_points_at_another_project(tmp_path):
    """The end-to-end shape of the finding: bake resolves vm.artifact.path."""
    from vmctl_core.promotion import bake_disk

    root = tmp_path / "work-1.0"
    (root / "vm").mkdir(parents=True)
    (root / "bundle.yaml").write_text(
        "bundle_format: 1\nvm:\n  artifact:\n    path: ../../victim.qcow2\n"
    )
    (tmp_path.parent / "victim.qcow2").write_bytes(b"another project's disk")
    with pytest.raises(ValueError, match="outside itself"):
        bake_disk(root, tmp_path / "out.qcow2")


def test_unpack_refuses_a_bundle_that_cannot_fit(tmp_path, monkeypatch):
    import shutil as _shutil

    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("work-1.0/vm/overlay.qcow2", b"small")

    class _Usage:
        total = free = used = 1 << 20  # 1 MiB free: below the headroom, so anything is refused

    monkeypatch.setattr(_shutil, "disk_usage", lambda p: _Usage)
    with pytest.raises(ValueError, match=r"only .* free"):
        unpack_bundle_zip(z, tmp_path / "dest")


def test_unpack_still_works_with_room(tmp_path):
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("work-1.0/vm/overlay.qcow2", b"small")
    root = unpack_bundle_zip(z, tmp_path / "dest")
    assert (root / "vm" / "overlay.qcow2").read_bytes() == b"small"


def test_plugin_entrypoint_stays_inside_the_plugin_dir():
    """The loader joins entrypoint to the plugin dir and exec's it, so a manifest must not be
    able to name a file elsewhere. Containment, not a privilege boundary: whoever writes the
    manifest can write the plugin beside it — but 'which file runs' stays answerable locally."""
    from vmctl_core.plugins.spec import PluginManifest

    assert PluginManifest(id="p", name="P").entrypoint == "plugin.py"
    assert PluginManifest(id="p", name="P", entrypoint="sub/plugin.py").entrypoint

    for escape in ("../../host.py", "/etc/cron.d/x.py", "sub/../../x.py", " "):
        with pytest.raises(Exception, match=r"entrypoint|validation"):
            PluginManifest(id="p", name="P", entrypoint=escape)


def test_aux_base_must_live_under_an_allowed_root(tmp_path):
    """vm.aux_disks[].base_path is an absolute HOST path by design (a shared OpenCore base, not a
    catalog id), so the bundle-relative guard cannot cover it. Unconfined, a crafted bundle could
    name any readable file and have bake flatten it into the disk the submitter downloads."""
    from vmctl_core.promotion import _aux_source_disks, sha256_file

    root = tmp_path / "work-1.0"
    (root / "vm").mkdir(parents=True)
    (root / "vm" / "aux-0.qcow2").write_bytes(b"overlay")

    bases = tmp_path / "bases"
    bases.mkdir()
    legit = bases / "opencore.qcow2"
    legit.write_bytes(b"shared base")
    outsider = tmp_path / "elsewhere" / "other.qcow2"
    outsider.parent.mkdir()
    outsider.write_bytes(b"someone else's disk")

    def _bundle(base_path):
        (root / "bundle.yaml").write_text(
            "bundle_format: 1\nvm:\n  aux_disks:\n"
            "    - overlay: vm/aux-0.qcow2\n"
            f"      base_path: {base_path}\n      bus: sata\n      boot: 1\n"
            f"      base_sha: {sha256_file(base_path)}\n"
        )

    _bundle(legit)
    assert _aux_source_disks(root, [bases])[0]["base"] == legit

    _bundle(outsider)
    with pytest.raises(ValueError, match="outside the allowed base roots"):
        _aux_source_disks(root, [bases])

    # no roots at all -> refuse rather than resolve anything
    _bundle(legit)
    with pytest.raises(ValueError, match="no allowed base roots"):
        _aux_source_disks(root, [])
