"""Promotion bundle format (research/29) — the shared writer/verifier seam.

A promotion ships a finished plugin + its VM artifact from a research project to
an exhibition deployment as ONE self-describing, checksum-signed directory:

    <plugin-id>-<version>/
      bundle.yaml                the index (this module reads/writes it)
      plugin/                    the plugin dir, VERBATIM — "runs unchanged"
      vm/base.ref.yaml           catalog entry of the golden base (+ sha256)
      vm/overlay.qcow2           the CoW delta (thin) — rebased onto the base on import
      vm/base.qcow2              fat profile only: the golden image itself
      vm/domain.template.xml     rendered libvirt domain
      conservation/…             optional dead-internet archive
      config/exhibition.config.yaml
      PROVENANCE.yaml
      CHECKSUMS.sha256           sha256 of every file — integrity + dedup

This module owns the FORMAT (yaml I/O, checksums, verify); the research-side
exporter (rvmc) and the exhibition-side importer both build on it so the two
ends agree by construction and can't drift. Verbatim-plugin is enforced by the
checksum file: an importer re-hashes and refuses a bundle where a single byte
of ``plugin/`` differs.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from .drive import ArtworkDrive

BUNDLE_FORMAT = 1
BUNDLE_YAML = "bundle.yaml"
CHECKSUMS = "CHECKSUMS.sha256"
PROVENANCE = "PROVENANCE.yaml"

sha256_file = ArtworkDrive.sha256_file


def write_yaml(path: str | Path, data: dict) -> None:
    Path(path).write_text(yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


def read_yaml(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text()) or {}


def iter_bundle_files(bundle_dir: str | Path):
    """Every file in the bundle except the top-level checksum file itself, as sorted relpaths.

    Only the manifest at ``root/CHECKSUMS.sha256`` is excluded — a file that merely
    shares that name deeper in the tree (e.g. ``plugin/CHECKSUMS.sha256``) is a real
    payload file and MUST be hashed/verified, so we anchor the compare on the relpath."""
    root = Path(bundle_dir)
    manifest = Path(CHECKSUMS)
    for p in sorted(root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(root)
            if rel != manifest:
                yield rel


def write_checksums(bundle_dir: str | Path) -> Path:
    """Write CHECKSUMS.sha256 over the whole bundle (sha256sum -c compatible)."""
    root = Path(bundle_dir)
    lines = [f"{sha256_file(root / rel)}  {rel.as_posix()}" for rel in iter_bundle_files(root)]
    out = root / CHECKSUMS
    out.write_text("\n".join(lines) + "\n")
    return out


def verify_bundle(bundle_dir: str | Path) -> dict:
    """Re-hash a bundle against its CHECKSUMS.sha256 + sanity-check bundle.yaml.

    Returns ``{ok, format, files, mismatched: [...], missing: [...], extra: [...]}``
    — ``ok`` only when every recorded file matches and nothing was added/removed."""
    root = Path(bundle_dir)
    out: dict = {
        "ok": False,
        "format": None,
        "files": 0,
        "mismatched": [],
        "missing": [],
        "extra": [],
        "unsafe": [],
    }
    cs = root / CHECKSUMS
    by = root / BUNDLE_YAML
    if not cs.is_file() or not by.is_file():
        out["error"] = "not a bundle (CHECKSUMS.sha256 / bundle.yaml missing)"
        return out
    out["format"] = read_yaml(by).get("bundle_format")

    recorded: dict[str, str] = {}
    for line in cs.read_text().splitlines():
        if line.strip():
            digest, _, rel = line.partition("  ")
            recorded[rel.strip()] = digest.strip()
    present = {rel.as_posix() for rel in iter_bundle_files(root)}

    root_res = root.resolve()
    for rel, digest in recorded.items():
        # Containment guard: a hand-edited entry must not point outside the
        # bundle (absolute path or ``../`` escape) and make verify read/hash an
        # arbitrary host file. Reject it before ever touching the filesystem.
        relp = Path(rel)
        if relp.is_absolute() or not (root_res / relp).resolve().is_relative_to(root_res):
            out["unsafe"].append(rel)
            continue
        p = root / rel
        if not p.is_file():
            out["missing"].append(rel)
        elif sha256_file(p) != digest:
            out["mismatched"].append(rel)
    out["extra"] = sorted(present - set(recorded))
    out["files"] = len(recorded)
    out["ok"] = (
        not out["mismatched"]
        and not out["missing"]
        and not out["extra"]
        and not out["unsafe"]
        and out["format"] == BUNDLE_FORMAT
    )
    if out["unsafe"]:
        out["error"] = "bundle references paths outside the bundle root"
    return out
