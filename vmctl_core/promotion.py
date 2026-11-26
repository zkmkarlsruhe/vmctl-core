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

import contextlib
import hashlib
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Sequence
from pathlib import Path

import yaml

from .atomicio import write_text_atomic
from .drive import ArtworkDrive

BUNDLE_FORMAT = 1
BUNDLE_YAML = "bundle.yaml"
CHECKSUMS = "CHECKSUMS.sha256"
PROVENANCE = "PROVENANCE.yaml"

sha256_file = ArtworkDrive.sha256_file


def write_yaml(path: str | Path, data: dict) -> None:
    # Atomic — bundle.yaml / PROVENANCE.yaml are part of a checksum-signed bundle; a torn write
    # would make verify_bundle report spurious mismatches and the importer reject a good bundle.
    write_text_atomic(path, yaml.safe_dump(data, sort_keys=False, allow_unicode=True))


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
        if p.is_file() and not p.is_symlink():  # a symlink's target is not bundle payload
            rel = p.relative_to(root)
            if rel != manifest:
                yield rel


def write_checksums(bundle_dir: str | Path) -> Path:
    """Write CHECKSUMS.sha256 over the whole bundle (sha256sum -c compatible)."""
    root = Path(bundle_dir)
    lines = [f"{sha256_file(root / rel)}  {rel.as_posix()}" for rel in iter_bundle_files(root)]
    out = root / CHECKSUMS
    # Atomic — a truncated CHECKSUMS.sha256 makes the whole bundle unverifiable.
    write_text_atomic(out, "\n".join(lines) + "\n")
    return out


#: A sealed bundle's files are read-only and its directories are read+execute but not writable —
#: so nothing can be added, removed or overwritten inside it without first taking the seal off.
_SEALED_FILE_MODE = 0o444
_SEALED_DIR_MODE = 0o555
_UNSEALED_FILE_MODE = 0o644
_UNSEALED_DIR_MODE = 0o755


def _chmod_tree(bundle_dir: str | Path, *, file_mode: int, dir_mode: int) -> int:
    """chmod every file and directory in the tree (the root last, so its own entries stay editable
    while we walk it). Returns the number of paths changed. Best-effort per path: a bundle can sit
    on a filesystem that does not carry unix modes (a FAT stick a colleague hands you), and there
    the chmod is a silent no-op rather than a failure."""
    root = Path(bundle_dir)
    changed = 0
    for p in sorted(root.rglob("*"), reverse=True):
        if p.is_symlink():
            continue  # chmod follows the link: never touch a target outside the tree
        with contextlib.suppress(OSError):
            p.chmod(dir_mode if p.is_dir() else file_mode)
            changed += 1
    with contextlib.suppress(OSError):
        root.chmod(dir_mode)
        changed += 1
    return changed


def seal_bundle(bundle_dir: str | Path) -> int:
    """Make a finished bundle read-only. Call it AFTER :func:`write_checksums`.

    A promoted bundle is the artefact an exhibition machine will import, possibly years later, and
    CHECKSUMS.sha256 is what tells that machine the bundle is intact. It is a good detector and a
    poor preventer: by the time it fires, whatever wrote into the bundle wrote a long time ago, and
    the promotion that produced it may no longer be reproducible. Sealing closes the ordinary ways
    a bundle rots in place — a half-finished re-promote, a plugin writing next to its own files, a
    hand-edit "just to fix one path" — by making them fail at the moment they happen, loudly, in
    front of whoever is doing it.

    It is a guardrail, not a boundary. The seal is unix modes on files the promoting user owns, so
    that user (and root) can take it off — deliberately, which is the point. A boundary against a
    process that WANTS to write here is a different mechanism: separate ownership, or a read-only
    mount for whatever runs artwork code. Nothing in this system currently hands an artwork process
    a writable path into the exhibition tree, and that is the property worth keeping true."""
    return _chmod_tree(bundle_dir, file_mode=_SEALED_FILE_MODE, dir_mode=_SEALED_DIR_MODE)


def unseal_bundle(bundle_dir: str | Path) -> int:
    """Give write permission back — needed before overwriting or deleting a sealed bundle.

    ``shutil.rmtree`` cannot remove entries from a 0555 directory, so every caller that supersedes
    or cleans up a promoted bundle has to come through here first."""
    return _chmod_tree(bundle_dir, file_mode=_UNSEALED_FILE_MODE, dir_mode=_UNSEALED_DIR_MODE)


def remove_sealed_tree(path: str | Path) -> None:
    """``shutil.rmtree`` that copes with sealed bundles inside ``path``.

    Deleting a project drive means deleting whatever promoted bundles it holds, and those are
    read-only (:func:`seal_bundle`). Plain rmtree cannot remove an entry from a 0555 directory, so
    a purge over a drive with a promoted bundle half-succeeds and leaves the rest standing, with
    only a warning in the log to say so.

    Implemented as chmod-the-tree-then-delete rather than rmtree's error hook, because the hook
    parameter that does this correctly (``onexc``) is 3.12+ and this package still supports 3.11 —
    the exhibition controller installs onto whatever interpreter the gallery machine has. Walking
    the tree twice costs nothing next to deleting a multi-GB bundle.
    """
    target = Path(path)
    if target.is_dir():
        _chmod_tree(target, file_mode=_UNSEALED_FILE_MODE, dir_mode=_UNSEALED_DIR_MODE)
    shutil.rmtree(target)


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
    # Symlinks are never hashed, packed or sealed; a bundle carrying one is not self-contained.
    out["unsafe"] = sorted(
        p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_symlink()
    )

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
        out["error"] = "bundle references paths outside the bundle root (or holds symlinks)"
    return out


def create_process_bundle(
    instance_dir: str | Path,
    bundle_dir: str | Path,
    *,
    provenance: dict,
) -> Path:
    """Seal a stopped process instance for exhibition, without disk conversion.

    vm/process.json and its relative images/media form a complete instance. The
    exhibition controller supplies a real display; host media is copied, never linked.
    Executable media is recorded so zip transport can restore its executable bits.
    """
    from .backends.process import SPEC_FILE, ProcessBackend, process_path

    instance = Path(instance_dir)
    backend = ProcessBackend(instance.name, instance_dir=instance)
    if backend.is_running():
        raise ValueError("stop the process instance before promotion")
    spec = backend.spec.model_copy(deep=True)
    if spec.cwd and spec.cwd != ".":
        process_path(instance, spec.cwd)
    if spec.alive_file:
        process_path(instance, spec.alive_file)
    if set(spec.images) & spec.media.keys():
        raise ValueError("process images and media overlap")
    root = Path(bundle_dir)
    root.mkdir(parents=True)  # a failed export must never replace an existing bundle
    try:
        vm = root / "vm"
        vm.mkdir()
        executables = []
        for name in [*spec.images, *spec.media]:
            source = process_path(instance, name)
            target = process_path(vm, name)
            if name in spec.images and not source.resolve().is_relative_to(instance.resolve()):
                raise ValueError(f"process image outside instance: {name}")
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            if name in spec.media:
                want = spec.media_sha256.get(name, "")
                if not want or sha256_file(target) != want.lower():
                    raise ValueError(f"process media sha256 mismatch: {name}")
                if source.stat().st_mode & 0o111:
                    executables.append(f"vm/{name}")
        if spec.cwd:
            (vm / spec.cwd).mkdir(parents=True, exist_ok=True)
        spec.virtual_display = False
        spec.display = ":0"
        spec.vnc_port = 0
        spec.env.pop("DISPLAY", None)
        spec.media = {name: name for name in spec.media}
        write_text_atomic(vm / SPEC_FILE, spec.model_dump_json(indent=2))
        write_yaml(
            root / BUNDLE_YAML,
            {
                "bundle_format": BUNDLE_FORMAT,
                "vm": {
                    "backend": "process",
                    "profile": "process",
                    "artifact": {"kind": "process", "path": f"vm/{SPEC_FILE}"},
                    "images": [f"vm/{name}" for name in spec.images],
                    "media": [f"vm/{name}" for name in spec.media],
                    "executables": executables,
                },
            },
        )
        write_yaml(root / PROVENANCE, provenance)
        write_checksums(root)
        seal_bundle(root)
        for name in executables:
            bundle_path(root, name).chmod(0o555)
    except BaseException:
        remove_sealed_tree(root)
        raise
    return root


# --- single-file transport (research/29 §8 handoff) ---------------------------
# A bundle on the drive is a directory; to carry it to a dedicated exhibition
# host it travels as ONE .zip. The exhibition host wants only the BAKED artwork
# image — a single standalone qcow2, not the golden + a CoW layer. So the package
# bakes on the way out: the drive's thin overlay is flattened onto its golden base
# (``qemu-img convert``) into one ``vm/disk.qcow2`` with no backing file, the base
# and base-ref are dropped, and ``bundle.yaml`` + ``CHECKSUMS.sha256`` are
# regenerated as a ``baked`` bundle. Nothing on the far side needs the golden or a
# catalog. The on-disk source bundle is never modified (baking works on a copy).


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _resolve_thin_base(bundle_dir: Path, catalog_path: str | Path) -> tuple[Path, str]:
    """Resolve+verify the golden base a thin bundle references. Returns (path, sha256)."""
    from .catalog import BaseImage

    ref = read_yaml(bundle_dir / "vm" / "base.ref.yaml")
    want = ref.get("sha256") or ""
    if not want:
        raise ValueError("thin bundle is missing golden base sha256 in vm/base.ref.yaml")
    fields = {k: v for k, v in ref.items() if k != "sha256"}
    base = BaseImage(**fields)
    p = base.resolved_path(Path(catalog_path).parent)
    if not p.is_file():
        raise FileNotFoundError(f"golden base not found for thin bundle: {p}")
    got = sha256_file(p)
    if got != want:
        raise ValueError(f"golden base sha256 mismatch (bundle wants {want}, catalog has {got})")
    return p, got


def _bake_one(overlay: Path, base: Path, out_disk: Path, qemu_img: str) -> str:
    """Flatten one overlay+base into a standalone backing-less qcow2. Source untouched."""
    with tempfile.TemporaryDirectory(prefix="vmctl-bake-") as td:
        tmp_overlay = Path(td) / "overlay.qcow2"
        shutil.copy2(overlay, tmp_overlay)
        # copy2 preserves the source mode, and a promoted bundle is SEALED read-only — so the
        # copy lands at 0444 and `qemu-img rebase` fails on it. Baking from a sealed bundle is
        # the normal case (the catalog serves zips straight off the drive rvmc promoted into),
        # so make our own scratch copy writable. The source stays untouched, sealed.
        tmp_overlay.chmod(0o644)
        # -u (unsafe): just rewrite the backing pointer to the resolved base; the
        # caller verified a thin base's recorded sha256 before reaching this step.
        # Then convert reads base+delta and emits one flat image.
        try:
            subprocess.run(
                [qemu_img, "rebase", "-u", "-b", str(base), "-F", "qcow2", str(tmp_overlay)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [qemu_img, "convert", "-O", "qcow2", str(tmp_overlay), str(out_disk)],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    qemu_img,
                    "compare",
                    "-f",
                    "qcow2",
                    "-F",
                    "qcow2",
                    str(tmp_overlay),
                    str(out_disk),
                ],
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            # the real reason (missing backing file, ENOSPC) is in stderr, not the exit code
            raise RuntimeError(
                f"{' '.join(e.cmd[:2])} failed: "
                f"{(e.stderr or e.stdout or b'').decode(errors='replace').strip()}"
            ) from e
    return sha256_file(out_disk)


def _main_base(root: Path, catalog_path: str | Path | None) -> Path:
    """The golden for a bundle's MAIN disk — embedded (fat) or resolved from the catalog."""
    embedded = root / "vm" / "base.qcow2"
    vm = read_yaml(root / BUNDLE_YAML).get("vm") or {}
    if embedded.is_file() and vm.get("profile") != "thin":
        return embedded
    if catalog_path:
        return _resolve_thin_base(root, catalog_path)[0]
    raise ValueError("thin bundle needs catalog_path to resolve the golden base for baking")


#: Free space the unpack refuses to eat into. The exhibition host's root filesystem carries the
#: running exhibit's disk; filling it stops the artwork, not just the import.
_UNPACK_HEADROOM_BYTES = 1 << 30  # 1 GiB


def bundle_path(root: Path, rel: str) -> Path:
    """Resolve a bundle-declared relative path, refusing anything outside the bundle.

    Every path a bundle names for itself goes through here. ``verify()`` already guarded the
    CHECKSUMS entries this way, but the paths bundle.yaml declares for its own disks did not:
    ``vm.artifact.path`` and each ``vm.aux_disks[].overlay`` were joined to the root and used
    straight away. CHECKSUMS is not a signature — the submitter writes it — so a bundle could
    declare ``path: ../../<other-project>/vm/overlay.qcow2``, pass verification, and have bake
    flatten ANOTHER project's disk into the image the submitter then downloads.
    """
    relp = Path(rel)
    root_res = root.resolve()
    if relp.is_absolute() or not (root_res / relp).resolve().is_relative_to(root_res):
        raise ValueError(f"bundle declares a path outside itself: {rel!r}")
    return root / relp


def _aux_source_disks(root: Path, base_roots: Sequence[Path] = ()) -> list[dict]:
    """Aux boot disks (e.g. OpenCore for macOS) a thin bundle declares in ``vm.aux_disks``.

    Each entry: ``{overlay: vm/aux-N.qcow2, base_path: <abs shared base>, base_sha, bus, boot}``.
    Unlike the main disk the aux base is a plain absolute path (not a catalog id): OpenCore
    is a shared read-only base, not a golden in the catalog. Returns resolved+verified specs
    in declaration (= boot) order."""
    vm = (read_yaml(root / BUNDLE_YAML).get("vm")) or {}
    out = []
    for a in vm.get("aux_disks") or []:
        overlay = bundle_path(root, a["overlay"])
        if not overlay.is_file():
            raise FileNotFoundError(f"aux overlay not in bundle: {overlay}")
        # base_path is an ABSOLUTE host path by design (a shared read-only base, not a catalog
        # id), so bundle_path() cannot confine it — and CHECKSUMS proves nothing here either,
        # since whoever writes the bundle writes the checksums. Unconfined, a crafted bundle
        # could name any readable file and have bake flatten it into the disk the submitter then
        # downloads. The producer always writes <catalog dir>/<aux.path>, so the catalog's own
        # directory is the honest boundary; the caller passes it.
        base = Path(a["base_path"])
        if not base_roots:
            raise ValueError(
                f"refusing to resolve aux base {base} — no allowed base roots were given "
                f"(pass base_roots, or catalog_path so it can be derived)"
            )
        resolved = base.resolve()
        if not any(resolved.is_relative_to(r) for r in base_roots):
            raise ValueError(
                f"aux base {base} is outside the allowed base roots "
                f"({', '.join(str(r) for r in base_roots)})"
            )
        if not base.is_file():
            raise FileNotFoundError(f"aux base not found: {base}")
        if not a.get("base_sha"):
            raise ValueError(f"thin bundle is missing aux base sha256 (base_sha): {base}")
        got = sha256_file(base)
        if got != a["base_sha"]:
            raise ValueError(f"aux base sha256 mismatch ({base}): want {a['base_sha']}, got {got}")
        out.append(
            {
                "overlay": overlay,
                "base": base,
                "bus": a.get("bus", "sata"),
                "boot": a.get("boot", 1),
            }
        )
    return out


def bake_disk(
    bundle_dir: str | Path,
    out_disk: str | Path,
    *,
    catalog_path: str | Path | None = None,
    qemu_img: str = "qemu-img",
) -> str:
    """Flatten a bundle's MAIN overlay chain into ONE standalone qcow2 at ``out_disk``.

    Resolves the base (from ``vm/base.qcow2`` if the bundle is fat, else from the
    catalog for a thin bundle), rebases a COPY of the overlay onto it, and
    ``qemu-img convert``s the copy to a backing-less image. The source overlay is
    untouched. Returns the sha256 of the baked disk. (Aux disks — macOS OpenCore —
    are handled by :func:`pack_bundle_zip`'s baked-multi path.)
    """
    root = Path(bundle_dir)
    vm = (read_yaml(root / BUNDLE_YAML).get("vm")) or {}
    if vm.get("backend") == "process":
        raise ValueError("process bundles contain raw images and do not need baking")
    overlay_rel = (vm.get("artifact") or {}).get("path") or "vm/overlay.qcow2"
    overlay = bundle_path(root, overlay_rel)
    if not overlay.is_file():
        raise FileNotFoundError(f"bundle has no overlay to bake: {overlay}")
    return _bake_one(overlay, _main_base(root, catalog_path), Path(out_disk), qemu_img)


def pack_bundle_zip(
    bundle_dir: str | Path,
    out_zip: str | Path,
    *,
    catalog_path: str | Path | None = None,
    base_roots: Sequence[str | Path] | None = None,
    qemu_img: str = "qemu-img",
) -> dict:
    """Pack a promotion bundle into ONE self-contained BAKED zip for an exhibition host.

    A bundle with a ``vm/`` section is baked: its overlay chain is flattened into a
    single standalone ``vm/disk.qcow2`` (the golden + base-ref are dropped), and the
    manifest is rewritten as a ``baked`` bundle. Process bundles carry raw images
    and media verbatim; no baking or catalog is needed. An already-baked bundle
    (``vm/disk.qcow2`` present) is repackaged verbatim; a plugin-only bundle (no
    ``vm/`` section) likewise. Returns ``{zip, bundle, profile, baked, disk_sha256,
    files}``. The source bundle directory is left untouched.
    """
    root = Path(bundle_dir)
    if not (root / BUNDLE_YAML).is_file():
        raise ValueError(f"not a bundle (no {BUNDLE_YAML}): {root}")
    by = read_yaml(root / BUNDLE_YAML)
    vm = by.get("vm") or {}
    already_baked = str(vm.get("profile", "")).startswith("baked")
    is_process = vm.get("backend") == "process"
    if is_process and not verify_bundle(root)["ok"]:
        raise ValueError("process bundle failed checksum verification")
    to_bake = bool(vm) and not already_baked and not is_process
    # Where an aux base may live. Defaults to the catalog's own directory, which is where the
    # producer puts it; an explicit list wins for a caller with a different layout.
    roots = [Path(r).resolve() for r in (base_roots or [])]
    if not roots and catalog_path:
        roots = [Path(catalog_path).resolve().parent]
    aux_src = _aux_source_disks(root, roots) if to_bake else []

    # The golden base, every CoW overlay (main + aux) and the base-ref never travel
    # in a baked package — the flattened standalone disks replace them.
    drop = set()
    if to_bake:
        drop = {"vm/base.qcow2", "vm/overlay.qcow2", "vm/base.ref.yaml"}
        drop.update(a["overlay"] for a in (vm.get("aux_disks") or []))
    out_res = Path(out_zip).resolve()
    entries: dict[str, tuple[str, object]] = {}
    for rel in iter_bundle_files(root):
        s = rel.as_posix()
        if s == BUNDLE_YAML:
            continue
        if s in drop:
            continue
        if (root / rel).resolve() == out_res:
            # Re-export where the target zip lives INSIDE the bundle dir: never pack the
            # output into itself. ZipFile(out_zip, "w") truncates it first, so z.write
            # would then read the very file it is writing -> a corrupt archive.
            continue
        entries[s] = ("path", root / rel)

    baked = False
    disk_sha = (vm.get("artifact") or {}).get("sha256", "") if already_baked else ""
    disk_shas: list[str] = []
    ready = (vm.get("artifact") or {}).get("ready_snapshot", "") or vm.get("ready_snapshot", "")
    domain_tmpl = vm.get("domain_template", "vm/domain.template.xml")
    tmpdir: tempfile.TemporaryDirectory | None = None
    # The bake steps below create tmpdir, so they MUST live inside this try: a bake
    # failure (qemu-img rebase/convert) would otherwise leak the TemporaryDirectory,
    # since the finally that owns its cleanup used to start only after baking.
    try:
        if to_bake and aux_src:
            # baked-multi: macOS-style (OpenCore aux disk[s] + main). Disks are ordered
            # aux-first, matching the domain's disk order (the template emits aux disks
            # ahead of the main clone). The importer maps them back positionally.
            tmpdir = tempfile.TemporaryDirectory(prefix="vmctl-pack-")
            disks_meta = []
            idx = 0
            for a in aux_src:
                out = Path(tmpdir.name) / f"disk-{idx}.qcow2"
                sha = _bake_one(a["overlay"], a["base"], out, qemu_img)
                disk_shas.append(sha)
                entries[f"vm/disk-{idx}.qcow2"] = ("path", out)
                disks_meta.append(
                    {
                        "path": f"vm/disk-{idx}.qcow2",
                        "sha256": sha,
                        "role": "aux",
                        "bus": a["bus"],
                        "boot": a["boot"],
                    }
                )
                idx += 1
            main_overlay = bundle_path(
                root, (vm.get("artifact") or {}).get("path") or "vm/overlay.qcow2"
            )
            out = Path(tmpdir.name) / f"disk-{idx}.qcow2"
            sha = _bake_one(main_overlay, _main_base(root, catalog_path), out, qemu_img)
            disk_shas.append(sha)
            entries[f"vm/disk-{idx}.qcow2"] = ("path", out)
            disks_meta.append({"path": f"vm/disk-{idx}.qcow2", "sha256": sha, "role": "main"})
            baked = True
            by["vm"] = {
                "profile": "baked-multi",
                "disks": disks_meta,
                "ready_snapshot": ready,
                "domain_template": domain_tmpl,
                # firmware/packages the exhibition host must provide (macOS: OVMF); the
                # baked image can't carry host firmware, so we declare the dependency.
                "host_requires": vm.get("host_requires", []),
            }
        elif to_bake:
            tmpdir = tempfile.TemporaryDirectory(prefix="vmctl-pack-")
            disk = Path(tmpdir.name) / "disk.qcow2"
            disk_sha = bake_disk(root, disk, catalog_path=catalog_path, qemu_img=qemu_img)
            entries["vm/disk.qcow2"] = ("path", disk)
            baked = True
            by["vm"] = {
                "profile": "baked",
                "artifact": {
                    "kind": "disk",
                    "path": "vm/disk.qcow2",
                    "sha256": disk_sha,
                    "ready_snapshot": ready,
                },
                "domain_template": domain_tmpl,
            }

        bundle_yaml_bytes = yaml.safe_dump(by, sort_keys=False, allow_unicode=True).encode()
        entries[BUNDLE_YAML] = ("bytes", bundle_yaml_bytes)

        lines = []
        for s in sorted(entries):
            kind, val = entries[s]
            digest = sha256_file(val) if kind == "path" else _digest_bytes(val)  # type: ignore[arg-type]
            lines.append(f"{digest}  {s}")
        checksums_bytes = ("\n".join(lines) + "\n").encode()

        top = root.name  # keep the <plugin>-<version>/ dir inside the zip
        out = Path(out_zip)
        with zipfile.ZipFile(out, "w", allowZip64=True) as z:
            for s in sorted(entries):
                kind, val = entries[s]
                # qcow2 is the bulk and barely compresses — STORE it (no CPU burn on
                # a multi-GB baked disk); DEFLATE the small text payload.
                comp = zipfile.ZIP_STORED if s.endswith(".qcow2") else zipfile.ZIP_DEFLATED
                if kind == "path":
                    z.write(val, f"{top}/{s}", compress_type=comp)  # type: ignore[arg-type]
                else:
                    z.writestr(f"{top}/{s}", val, compress_type=comp)  # type: ignore[arg-type]
            z.writestr(f"{top}/{CHECKSUMS}", checksums_bytes, compress_type=zipfile.ZIP_DEFLATED)
    finally:
        if tmpdir is not None:
            tmpdir.cleanup()

    return {
        "zip": str(out),
        "bundle": top,
        "profile": (by.get("vm") or {}).get("profile", "plugin-only") if vm else "plugin-only",
        "baked": baked,
        "disk_sha256": disk_sha,  # main disk (single baked); "" for baked-multi
        "disk_sha256s": disk_shas,  # all baked disks, aux-first (baked-multi)
        "files": len(entries),
    }


def unpack_bundle_zip(zip_path: str | Path, dest_dir: str | Path) -> Path:
    """Extract a bundle zip into ``dest_dir`` (zip-slip guarded). Returns the bundle root.

    The zip must hold exactly one top-level ``<plugin>-<version>/`` directory. The
    caller verifies integrity via :func:`verify_bundle` on the returned path.
    """
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    dest_res = dest.resolve()
    tops: set[str] = set()
    with zipfile.ZipFile(zip_path) as z:
        # Refuse a bundle that cannot fit BEFORE writing any of it. Bundles are legitimately
        # multi-GB, so the bound is the disk itself rather than a fixed cap: the exhibition
        # importer unpacks into a temp dir on the same filesystem as the running exhibit's
        # qcow2, so a 5 MB zip declaring a 500 GB member would ENOSPC the artwork that is
        # currently on the wall. The declared sizes are attacker-controlled, but a lie in
        # either direction is caught — too small and the extract itself hits ENOSPC, too
        # large and we refuse a bundle that would not have fit anyway.
        declared = sum(max(i.file_size, 0) for i in z.infolist())
        free = shutil.disk_usage(dest).free
        if declared > free - _UNPACK_HEADROOM_BYTES:
            raise ValueError(
                f"bundle expands to {declared} bytes; only {free} free at {dest} "
                f"(keeping {_UNPACK_HEADROOM_BYTES} headroom)"
            )
        for info in z.infolist():
            name = info.filename
            if not (dest / name).resolve().is_relative_to(dest_res):
                raise ValueError(f"unsafe path in zip (escapes dest): {name}")
            parts = Path(name).parts
            if parts:
                tops.add(parts[0])
            z.extract(info, dest)
    if len(tops) != 1:
        raise ValueError(f"zip must contain exactly one bundle dir, found: {sorted(tops)}")
    root = dest / tops.pop()
    vm = (read_yaml(root / BUNDLE_YAML).get("vm") or {}) if (root / BUNDLE_YAML).is_file() else {}
    if vm.get("backend") == "process":
        if not verify_bundle(root)["ok"]:
            raise ValueError("unpacked process bundle failed checksum verification")
        from .backends.process import ProcessSpec, process_path

        definition = bundle_path(root, vm["artifact"]["path"])
        spec = ProcessSpec.model_validate_json(definition.read_text())
        if spec.cwd and spec.cwd != ".":
            process_path(definition.parent, spec.cwd).mkdir(parents=True, exist_ok=True)
        for name in vm.get("executables", []):
            bundle_path(root, name).chmod(0o755)
    return root
