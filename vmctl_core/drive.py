"""The artwork drive — per-artwork, storage-first lifecycle (research/68).

The platform's unit is the artwork: one project IS one artwork, and the drive is
its canonical on-disk home — the original files, its helpers, and every stage's
output in ONE portable directory. ``drive.yaml`` records identity, provenance and
where the artwork stands in the lifecycle (analysis → workbench → exhibition).

VM disks deliberately stay OUT of the drive (overlays are host-bound backing
chains, GBs, reproducible); instance *recipes* go in the manifest instead, so a
drive re-clones anywhere the base catalog exists. The one deliberate export point
for disk state is the exhibition bundle under ``exhibition/`` (research/29 §3-A).

Layout (every subdir created by :meth:`ArtworkDrive.create`):

    <drives_root>/<artwork_id>/
      drive.yaml       manifest (:class:`DriveManifest`)
      artwork/         the ORIGINAL bundle, as-is, immutable — never modified
      unpacked/        derived working tree (analysis writes, workbench reads)
      helpers/         legacy runtimes/tools THIS artwork needs (tools-box resolved)
      analysis/        stage 1 (autopsy): kb/, runbook, run_graph, suggestions
      work/            stage 2: plugin/ notes/ uploads/ datalink/ captures/ archive/
      exhibition/      stage 3: emitted promotion bundles (research/29 layout)

Stage is a marker, not a gate — going back from workbench to analysis is normal.
"""

from __future__ import annotations

import hashlib
from datetime import date
from pathlib import Path

import yaml
from pydantic import BaseModel, Field

STAGES = ("intake", "analysis", "workbench", "exhibition")

#: every directory a drive owns, relative to its root (order = creation order)
SUBDIRS = (
    "artwork",
    "unpacked",
    "helpers",
    "analysis",
    "work/plugin",
    "work/notes",
    "work/uploads",
    "work/datalink",
    "work/captures",
    "work/archive",
    "exhibition",
)

MANIFEST_NAME = "drive.yaml"


class ArtworkMeta(BaseModel):
    id: str
    title: str = ""
    artist: str = ""
    received: str = ""  # ISO date the bundle arrived
    provenance: dict = Field(default_factory=dict)  # source, license, …


class AnalysisRef(BaseModel):
    """Stage-1 summary — the autopsy job that filled ``analysis/``."""

    job_id: str = ""  # == artwork id by convention
    status: str = ""  # queued | running | done | failed
    base_suggestion: str = ""  # catalog base_id, pre-fills "start VM"


class HelperRef(BaseModel):
    """One resolved legacy runtime/tool copied into ``helpers/``."""

    id: str
    source: str = "tools-box"
    sha256: str = ""


class InstanceRecipe(BaseModel):
    """Enough to re-clone a workbench VM anywhere the base catalog exists —
    the portable stand-in for the host-bound overlay/XML."""

    base_id: str
    hw: dict = Field(default_factory=dict)  # Hardware overrides
    ready_snapshot: str = ""


class WorkbenchRef(BaseModel):
    plugin_id: str = ""
    instances: list[InstanceRecipe] = Field(default_factory=list)


class ExhibitionRef(BaseModel):
    bundles: list[str] = Field(default_factory=list)  # dir names under exhibition/


class DriveManifest(BaseModel):
    drive_format: int = 1
    artwork: ArtworkMeta
    stage: str = "intake"
    analysis: AnalysisRef = Field(default_factory=AnalysisRef)
    helpers: list[HelperRef] = Field(default_factory=list)
    workbench: WorkbenchRef = Field(default_factory=WorkbenchRef)
    exhibition: ExhibitionRef = Field(default_factory=ExhibitionRef)


class ArtworkDrive:
    """One artwork's drive: layout + manifest I/O + stage transitions.

    Instances are cheap path wrappers; nothing touches disk until
    :meth:`create` / :meth:`load` / :meth:`save`.
    """

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    # --- layout -------------------------------------------------------------
    @property
    def manifest_path(self) -> Path:
        return self.path / MANIFEST_NAME

    @property
    def artwork_dir(self) -> Path:
        return self.path / "artwork"

    @property
    def unpacked_dir(self) -> Path:
        return self.path / "unpacked"

    @property
    def helpers_dir(self) -> Path:
        return self.path / "helpers"

    @property
    def analysis_dir(self) -> Path:
        return self.path / "analysis"

    @property
    def work_dir(self) -> Path:
        return self.path / "work"

    @property
    def plugin_dir(self) -> Path:
        return self.path / "work" / "plugin"

    @property
    def notes_dir(self) -> Path:
        return self.path / "work" / "notes"

    @property
    def uploads_dir(self) -> Path:
        return self.path / "work" / "uploads"

    @property
    def datalink_dir(self) -> Path:
        return self.path / "work" / "datalink"

    @property
    def captures_dir(self) -> Path:
        return self.path / "work" / "captures"

    @property
    def archive_dir(self) -> Path:
        return self.path / "work" / "archive"

    @property
    def exhibition_dir(self) -> Path:
        return self.path / "exhibition"

    @property
    def exists(self) -> bool:
        """A drive exists once its manifest does (bare dirs are just dirs)."""
        return self.manifest_path.exists()

    # --- creation -----------------------------------------------------------
    @classmethod
    def create(cls, drives_root: str | Path, artwork_id: str, *, title: str = "") -> ArtworkDrive:
        """Create (or complete) the drive skeleton for ``artwork_id``. Idempotent:
        directories are ensured on every call, ``drive.yaml`` is written only when
        missing — an existing manifest is NEVER touched."""
        if not artwork_id or "/" in artwork_id or artwork_id in (".", ".."):
            raise ValueError(f"invalid artwork id {artwork_id!r}")
        drive = cls(Path(drives_root) / artwork_id)
        for sub in SUBDIRS:
            (drive.path / sub).mkdir(parents=True, exist_ok=True)
        if not drive.manifest_path.exists():
            drive.save(
                DriveManifest(
                    artwork=ArtworkMeta(
                        id=artwork_id, title=title, received=date.today().isoformat()
                    )
                )
            )
        return drive

    # --- manifest I/O ---------------------------------------------------------
    def load(self) -> DriveManifest:
        data = yaml.safe_load(self.manifest_path.read_text()) or {}
        return DriveManifest(**data)

    def save(self, manifest: DriveManifest) -> None:
        if manifest.stage not in STAGES:
            raise ValueError(f"unknown stage {manifest.stage!r} (expected one of {STAGES})")
        self.manifest_path.write_text(
            yaml.safe_dump(manifest.model_dump(), sort_keys=False, allow_unicode=True)
        )

    # --- stage --------------------------------------------------------------
    def set_stage(self, stage: str) -> DriveManifest:
        """Move the marker (not a gate — any direction is legal)."""
        if stage not in STAGES:
            raise ValueError(f"unknown stage {stage!r} (expected one of {STAGES})")
        m = self.load()
        m.stage = stage
        self.save(m)
        return m

    # --- checksums ------------------------------------------------------------
    @staticmethod
    def sha256_file(path: str | Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    def artwork_checksums(self) -> dict[str, str]:
        """sha256 per file under ``artwork/`` (relpath → digest) — the integrity
        record of the immutable original."""
        out: dict[str, str] = {}
        for p in sorted(self.artwork_dir.rglob("*")):
            if p.is_file():
                out[str(p.relative_to(self.artwork_dir))] = self.sha256_file(p)
        return out
