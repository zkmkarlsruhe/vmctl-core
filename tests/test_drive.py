"""ArtworkDrive (research/68): skeleton, idempotency, manifest, stages, checksums."""

import threading
import time

import pytest
import yaml

from vmctl_core.drive import SUBDIRS, ArtworkDrive, DriveManifest
from vmctl_core.network_config import NETWORK_CONFIG_NAME, Endpoint, NetworkConfig


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


def test_stage_transitions(tmp_path):
    d = ArtworkDrive.create(tmp_path, "aw")
    assert d.set_stage("analysis").stage == "analysis"
    assert d.set_stage("workbench").stage == "workbench"
    # not a gate: going back is legal
    assert d.set_stage("analysis").stage == "analysis"
    with pytest.raises(ValueError):
        d.set_stage("museum")


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


def test_artwork_checksums(tmp_path):
    d = ArtworkDrive.create(tmp_path, "aw")
    (d.artwork_dir / "bundle.zip").write_bytes(b"original bytes")
    (d.artwork_dir / "sub").mkdir()
    (d.artwork_dir / "sub" / "readme.txt").write_text("hi")
    sums = d.artwork_checksums()
    assert set(sums) == {"bundle.zip", "sub/readme.txt"}
    assert sums["bundle.zip"] == ArtworkDrive.sha256_file(d.artwork_dir / "bundle.zip")


def _net_config() -> NetworkConfig:
    return NetworkConfig(
        transport={"mode": "transparent"},
        endpoints=[Endpoint(url="http://x/", method="GET", trigger="load")],
    )


def test_concurrent_stage_and_network_config_no_lost_update(tmp_path, monkeypatch):
    """set_stage() and save_network_config() each do load->mutate-ONE-field->save. Without the
    per-drive lock, two concurrent sequences interleave and whoever saves last writes a snapshot
    missing the OTHER's field (lost update). Widen the load->save window so an unlocked pair would
    reliably lose one field, then assert BOTH the stage AND the network_config pointer survived."""
    d = ArtworkDrive.create(tmp_path, "aw")

    real_save = ArtworkDrive.save

    def slow_save(self, manifest):
        time.sleep(0.05)  # widen the mutate window an unlocked concurrent pair would race in
        return real_save(self, manifest)

    monkeypatch.setattr(ArtworkDrive, "save", slow_save)

    barrier = threading.Barrier(2)

    def do_stage():
        barrier.wait()
        d.set_stage("workbench")

    def do_nc():
        barrier.wait()
        d.save_network_config(_net_config())

    a = threading.Thread(target=do_stage)
    b = threading.Thread(target=do_nc)
    a.start()
    b.start()
    a.join()
    b.join()

    m = d.load()
    assert m.stage == "workbench"  # not clobbered back to intake by the nc save
    assert m.analysis.network_config == NETWORK_CONFIG_NAME  # not clobbered by the stage save
