"""ArtworkDrive (research/68): skeleton, idempotency, manifest."""

import pytest
import yaml

from vmctl_core.drive import SUBDIRS, ArtworkDrive, DriveManifest


def test_create_skeleton(tmp_path):
    d = ArtworkDrive.create(tmp_path, "sample-work", title="Sample Work")
    assert d.path == tmp_path / "sample-work"
    for sub in SUBDIRS:
        assert (d.path / sub).is_dir(), sub
    assert d.exists
    m = d.load()
    assert m.drive_format == 1
    assert m.artwork.id == "sample-work"
    assert m.artwork.title == "Sample Work"
    assert m.stage == "intake"


def test_create_is_idempotent_and_never_touches_manifest(tmp_path):
    d = ArtworkDrive.create(tmp_path, "aw")
    m = d.load()
    m.stage = "workbench"
    m.artwork.title = "edited by hand"
    d.save(m)
    d2 = ArtworkDrive.create(tmp_path, "aw", title="would clobber")
    m2 = d2.load()
    assert m2.stage == "workbench"
    assert m2.artwork.title == "edited by hand"


def test_invalid_ids_rejected(tmp_path):
    for bad in ("", "a/b", ".", ".."):
        with pytest.raises(ValueError):
            ArtworkDrive.create(tmp_path, bad)


def test_manifest_roundtrip_yaml(tmp_path):
    d = ArtworkDrive.create(tmp_path, "aw")
    m = d.load()
    m.analysis.job_id = "aw"
    m.analysis.base_suggestion = "winxp-sp3-ie6"
    m.workbench.plugin_id = "aw"
    d.save(m)
    raw = yaml.safe_load(d.manifest_path.read_text())
    assert raw["analysis"]["base_suggestion"] == "winxp-sp3-ie6"
    assert DriveManifest(**raw).workbench.plugin_id == "aw"
