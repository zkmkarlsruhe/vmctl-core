"""The tools box — a catalogued file database of legacy runtimes/drivers.

Holds the binaries needed to make legacy-OS artworks run (virtio-win drivers,
Flash 32.0.0.371, Java, QuickTime, Shockwave, Pulse 3D, …) with provenance, so a
researcher (or the AI) can pick the right artifacts and hand them to a guest —
either insert an ISO/driver disc as a CD, or pack installers into a fakeCD.

Layout (per research/10):
    <root>/<os>/<runtime>/<version>/<filename>
    <root>/<os>/<runtime>/<version>/SOURCE.md      # url, date, licence
    <root>/catalog.json                            # the database
"""

from __future__ import annotations

import builtins
import contextlib
import hashlib
import json
import re
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .atomicio import write_text_atomic


def _now() -> str:
    """ISO-8601 local timestamp (matches the controller's audit.log format)."""
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# Guest-OS taxonomy for tool compatibility. Aligned with the base-image catalog's
# free-form `os` labels (see vmctl_core.catalog.BaseImage.os: "windows-xp", "linux", …)
# so a tool's os_compat can be matched directly against a base's os. "any" = runs
# everywhere (e.g. plain archives); an empty os_compat means "unclassified" — we
# don't know yet, so it is still shown rather than hidden.
OS_TAXONOMY: tuple[str, ...] = (
    "windows-9x",  # Windows 95/98/ME
    "windows-2000",
    "windows-xp",
    "windows-7",
    "windows-8",
    "linux",
    "mac-os-9",  # classic Mac OS
    "mac-os-x",
    "any",  # OS-agnostic (archives, cross-platform formats)
)


# Canonical tool taxonomy (2026-07 refactor). `category` is the top-level FUNCTION —
# what the tool DOES — and is the primary axis of the canonical id (see canonical_tool_id).
# SCOPE: the catalog holds ONLY tooling you push+install INTO a guest to REPAIR/restore a
# specific artwork so it runs. Everything fixed at golden-build time is out — goldens are
# built outside vmctl WITH their drivers/hardware profile baked in, so `driver` is NOT a
# category (a driver is a base-image concern, not a per-artwork repair). Also out:
# out-of-guest/host tooling (disk imaging, forensic boot CDs, emulators, OS media) and
# exhibition-deployment tooling (kiosk/autologin/watchdog — runs the PC, not the artwork).
# `family` (the format/vendor line: flash, java, director, dotnet, …) is a separate axis,
# carried by the `runtime` field for back-compat.
CATEGORIES: tuple[str, ...] = (
    "runtime",  # period players/plugins that execute an artwork format (Flash, Director, QuickTime, Java, VRML, …)
    "redist",  # runtime redistributables / frameworks installed per-artwork (.NET, VC++, DirectX, MFC, VB6)
    "unpacker",  # archive/format extractors for artwork payloads (StuffIt Expander, The Unarchiver/unar)
)

# Legacy free-text `category` values (pre-refactor, still in old catalogs) -> canonical
# function. Used by the id/category migration (scripts/migrate_tool_ids.py) and tolerated
# on load so old entries keep resolving until migrated. (virtio-driver has no target — a
# driver belongs in the golden, not this catalog; no such entries exist to migrate.)
LEGACY_CATEGORY_MAP: dict[str, str] = {
    "flash-player": "runtime",
    "java-runtime": "runtime",
    "quicktime-media": "runtime",
    "shockwave-director": "runtime",
    "vrml-3d-viewer": "runtime",
    "svg-viewer": "runtime",
    "silverlight-runtime": "runtime",
    "realmedia-codec": "runtime",
    "audio-music-engine": "runtime",
    "authorware-player": "runtime",
    "pulse3d-viewer": "runtime",
    "video-codec-pack": "runtime",
    "system-component": "redist",
}
TOOL_CLASSES: tuple[str, ...] = (
    "browser-plugin",
    "standalone-runtime",
    "codec-pack",
    "driver",
    "system-component",
)
BROWSER_INTEGRATIONS: tuple[str, ...] = (
    "npapi",
    "activex",
    "ppapi",
    "standalone",
    "activex+npapi",
)
# Relationship vocabulary (research/65 §B — the dependency/Technical-Environment graph).
# A relation is a dict on Tool.relations: {rel, target_id?, target?, mime?, note?, confidence?}.
#   target_id -> another tool's canonical id (software<->software edge)
#   target    -> a FORMAT identifier for reads_format/writes_format (PRONOM PUID like
#                "fmt/507", or a bare MIME); mime= carries the MIME when target is a PUID.
# software<->software: alternative_to (real-alternative<->RealPlayer), depends_on
# (Director projector -> its Xtras), bundled_with/repackages, replaces/followed_by
# (.NET 4.0 -> 4.8). software->format: reads_format/writes_format (PRONOM read/write links).
REL_TYPES: tuple[str, ...] = (
    "alternative_to",
    "depends_on",
    "bundled_with",
    "repackages",
    "replaces",
    "followed_by",
    "reads_format",
    "writes_format",
)

INSTALL_MODES: tuple[str, ...] = ("interactive", "silent-supported", "network-bootstrap")
SCAN_STATUSES: tuple[str, ...] = ("clean", "flagged", "unscanned")
ENRICHMENT_STATUSES: tuple[str, ...] = ("stub", "draft", "reviewed", "published")

# Fields that count toward a tool's completeness meter (the AI-leverage must-haves).
MUST_HAVE: tuple[str, ...] = (
    "category",
    "tool_class",
    "vendor",
    "browser_integration",
    "handles_mime",
    "handles_ext",
    "implements_spec",
    "requires_browser",
    "install_mode",
    "scan_status",
    "description_short",
)


def _slugify(value: str) -> str:
    """One canonical-id segment: lowercase, non-alphanumeric runs -> a single '-'.

    Dots collapse too, so a version like ``32.0.0.465`` becomes ``32-0-0-465`` and
    ``7.02`` becomes ``7-02`` — segments are joined by '.', so no dot survives inside one.
    """
    return re.sub(r"[^a-z0-9]+", "-", str(value).strip().lower()).strip("-")


def canonical_tool_id(category: str, family: str, slug: str, version: str) -> str:
    """Build the canonical, collision-resistant tool id (2026-07 scheme).

        <category>.<family>.<slug>.<version>

    e.g. canonical_tool_id("runtime", "flash", "player-sa", "32.0.0.465")
         -> "runtime.flash.player-sa.32-0-0-465"
         canonical_tool_id("runtime", "authorware", "web-player", "7.02")
         -> "runtime.authorware.web-player.7-02"

    The variant (npapi/activex/sa/…) is NOT a separate id segment — when a family/
    version ships multiple variants they are distinguished IN THE SLUG (player-npapi,
    player-activex, player-sa), which reads cleaner and keeps `variant` a pure metadata
    field. Category is validated against CATEGORIES (the function axis); empty
    family/slug/version raise — the id must be fully reconstructable from its parts.
    """
    cat = coerce_category(category)
    if cat not in CATEGORIES:
        raise ValueError(f"unknown tool category {category!r} — must be one of {CATEGORIES}")
    parts = [cat, _slugify(family), _slugify(slug), _slugify(version)]
    if not all(parts):
        raise ValueError(
            f"canonical id needs non-empty category/family/slug/version; got "
            f"category={category!r} family={family!r} slug={slug!r} version={version!r}"
        )
    return ".".join(parts)


def coerce_category(value: str) -> str:
    """Map a possibly-legacy `category` to a canonical function; pass canonical through."""
    v = (value or "").strip().lower()
    if v in CATEGORIES:
        return v
    return LEGACY_CATEGORY_MAP.get(v, v)


def tool_matches_os(os_compat: list[str], base_os: str | None) -> bool:
    """Does a tool (by its os_compat list) match a given base-image os?

    A tool matches when its os_compat contains `base_os`, contains "any", or is
    empty/unknown (treated as unclassified — still surfaced). With no base_os to
    match against, everything matches.
    """
    if not base_os:
        return True
    if not os_compat:  # unclassified — show it
        return True
    return base_os in os_compat or "any" in os_compat


@dataclass
class Tool:
    id: str
    name: str
    os: str  # winxp | win98 | macos9 | linux | cross
    runtime: str  # flash | java | quicktime | shockwave | pulse3d | drivers | ...
    version: str
    variant: str = ""  # activex | npapi | debug | installer | iso | ...
    kind: str = "installer"  # installer | iso | driver | archive
    path: str = ""  # relative to root
    size: int = 0
    sha256: str = ""
    source: str = ""  # where it came from (url)
    license: str = ""  # licence note (abandonware / vendor-EOL / redistributable)
    stage: str = "art"  # base (bake into image) | art (per-artwork)
    notes: str = ""
    present: bool = True  # file actually on disk (vs catalogued-but-to-fetch)
    os_compat: list[str] = field(default_factory=list)  # guest OSes this works on
    # (OS_TAXONOMY); [] = unclassified

    # --- provenance: where it came from, who put it here, and the proof ------
    # `source` (above) is kept for back-compat (free-form url). The pair below
    # separates the human landing page from the verified direct download.
    source_page: str = ""  # human-readable landing page (archive.org/details/…)
    download_url: str = ""  # the verified direct file URL the binary came from
    found_by: str = ""  # who/what discovered it (person or sourcing agent)
    found_via: str = ""  # how it was found (search query / path / page)
    added_by: str = ""  # who catalogued it into the box
    added_at: str = ""  # ISO-8601 when it was catalogued
    verified: bool = False  # binary fetch-verified at source (HTTP 200 + bytes)
    verified_at: str = ""  # ISO-8601 when last verified
    verify_evidence: str = ""  # the proof: curl status/Content-Length, checksum note
    # Append-only provenance log for THIS tool: [{ts, who, action, note, …}, …].
    # Survives independently of the global state_dir/audit.log and is what the
    # metadata viewer renders as a timeline.
    history: list[dict] = field(default_factory=list)

    # --- enrichment metadata (research/65 "first slice") ---------------------
    # Classification (controlled vocab — see CATEGORIES / TOOL_CLASSES below).
    category: str = ""  # canonical FUNCTION: runtime | redist | driver | unpacker | provisioning
    # Canonical-id axes (2026-07). `family` = format/vendor line (flash, director, dotnet,
    # stuffit …); defaults to `runtime` for back-compat. `slug` = the short stable handle
    # inside the family (player-sa, web-player, framework). Together with version/variant
    # they reconstruct the canonical id (see canonical_id / canonical_tool_id).
    family: str = ""
    slug: str = ""
    tool_class: str = (
        ""  # browser-plugin | standalone-runtime | codec-pack | driver | system-component
    )
    vendor: str = ""  # who made the software (≠ source, which is where the file came from)
    # What-it-handles — the AI tool-selection core (artwork asset -> runtime).
    handles_mime: list[str] = field(default_factory=list)  # ["model/vrml", …]
    handles_ext: list[str] = field(default_factory=list)  # [".wrl", ".wrz", …]
    implements_spec: list[str] = field(default_factory=list)  # ["VRML97", "ISO/IEC 14772-1"]
    browser_integration: str = ""  # npapi | activex | ppapi | standalone | activex+npapi
    requires_browser: list[str] = field(default_factory=list)  # ["ie6", "firefox-1.x", …]
    install_mode: str = ""  # interactive | silent-supported | network-bootstrap
    # Trust / security — these legacy runtimes are deliberately insecure.
    scan_status: str = "unscanned"  # clean | flagged | unscanned
    known_cves: list[str] = field(default_factory=list)
    network_required: bool = False  # installer phones home (pairs with install_mode)
    # Editorial + relationships.
    description_short: str = ""  # ≤200 chars; the AI one-liner / portal blurb
    relations: list[dict] = field(
        default_factory=list
    )  # [{rel, target_id?, target_name?, note?}, …]
    # Enrichment workflow state (completeness + missing fields are COMPUTED, not stored).
    enrichment_status: str = "stub"  # stub | draft | reviewed | published

    def matches_os(self, base_os: str | None) -> bool:
        """Compatible with a base image whose os is `base_os`? See tool_matches_os."""
        return tool_matches_os(self.os_compat, base_os)

    @property
    def canonical_id(self) -> str:
        """The id this tool SHOULD have under the canonical scheme (see canonical_tool_id).

        Uses `family` (falling back to `runtime`) and `slug`. Raises if the parts are
        insufficient — callers that want a best-effort check should catch ValueError.
        """
        return canonical_tool_id(
            self.category, self.family or self.runtime, self.slug, self.version
        )

    def log_event(self, action: str, *, by: str = "?", note: str = "", **extra) -> dict:
        """Append one event to this tool's provenance history and return it."""
        ev = {"ts": _now(), "who": by, "action": action}
        if note:
            ev["note"] = note
        ev.update(extra)
        self.history.append(ev)
        return ev

    # --- computed enrichment views (never stored; can't drift) ---------------
    def missing_must_haves(self) -> list[str]:
        """MUST_HAVE fields that are still empty — the 'needs enrichment' list."""
        out = []
        for f in MUST_HAVE:
            v = getattr(self, f, None)
            # scan_status seeds to "unscanned"; treat that as not-yet-done.
            if not v or (f == "scan_status" and v == "unscanned"):
                out.append(f)
        return out

    def completeness(self) -> int:
        """Percent of MUST_HAVE fields populated (0-100), for the UI meter."""
        done = len(MUST_HAVE) - len(self.missing_must_haves())
        return round(100 * done / len(MUST_HAVE)) if MUST_HAVE else 100

    def tool_card(self) -> dict:
        """Denormalized digest the AI reads first (research/65 §D). Derived, read-only."""
        gotchas: list[str] = []
        if self.install_mode == "network-bootstrap" or self.network_required:
            gotchas.append(
                "network-bootstrap installer — vendor URLs may be dead; host payload locally"
            )
        if self.known_cves:
            gotchas.append(f"keep VM offline — known CVEs ({len(self.known_cves)})")
        return {
            "what": " · ".join(
                p
                for p in (
                    self.tool_class,
                    self.category,
                    (self.implements_spec[0] if self.implements_spec else ""),
                )
                if p
            ),
            "vendor": self.vendor,
            "runs_content": list(self.handles_mime),
            "for_extensions": list(self.handles_ext),
            "implements": list(self.implements_spec),
            "needs_os": list(self.os_compat),
            "needs_browser": list(self.requires_browser),
            "integration": self.browser_integration,
            "deploy": {"iso": "iso-insert", "driver": "driver-bind"}.get(self.kind, "fakecd"),
            "gotchas": gotchas,
            "verified": self.verified,
            "completeness": self.completeness(),
        }

    def as_detail(self) -> dict:
        """Full record + computed enrichment views, for the metadata viewer."""
        d = asdict(self)
        d["tool_card"] = self.tool_card()
        d["completeness"] = self.completeness()
        d["needs_enrichment"] = self.missing_must_haves()
        return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class ToolsLibrary:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._catalog = self.root / "catalog.json"
        self.tools: dict[str, Tool] = {}
        self.load()

    def load(self) -> None:
        if self._catalog.exists():
            data = json.loads(self._catalog.read_text())
            # Tolerate older catalogs that predate a field (e.g. os_compat): keep
            # only keys Tool knows, and let dataclass defaults fill the rest.
            known = set(Tool.__dataclass_fields__)
            self.tools = {
                t["id"]: Tool(**{k: v for k, v in t.items() if k in known})
                for t in data.get("tools", [])
            }

    def save(self) -> None:
        # catalog.json is the source of truth — write atomically so a crash mid-write
        # can't leave a truncated file that fails to parse on the next load().
        write_text_atomic(
            self._catalog,
            json.dumps({"tools": [asdict(t) for t in self.tools.values()]}, indent=2),
        )

    def list(
        self,
        os: str | None = None,
        runtime: str | None = None,
        *,
        q: str | None = None,
        os_exact: str | None = None,
        kind: str | None = None,
        stage: str | None = None,
        present: bool | None = None,
    ) -> list[Tool]:
        """List tools, optionally filtered.

        `os` is matched against each tool's os_compat with base-matching semantics
        (contains os, contains "any", or unclassified → match) — i.e. "tools usable
        on a guest whose base os is <os>". Use a value from OS_TAXONOMY.

        Extra filters (all ANDed; None = no constraint):
          q          free-text substring over id / name / notes (case-insensitive)
          os_exact   exact match on the legacy single `os` label (winxp / win98 / ...)
          runtime    exact match on runtime
          kind       exact match on kind (installer / iso / driver / archive)
          stage      exact match on stage (base / art)
          present    only files on disk (True) / only catalogued-but-missing (False)
        """
        needle = (q or "").strip().lower()

        def keep(t: Tool) -> bool:
            if not t.matches_os(os):
                return False
            if runtime is not None and t.runtime != runtime:
                return False
            if os_exact is not None and t.os != os_exact:
                return False
            if kind is not None and t.kind != kind:
                return False
            if stage is not None and t.stage != stage:
                return False
            if present is not None and t.present is not present:
                return False
            return not (needle and needle not in f"{t.id} {t.name} {t.notes}".lower())

        return [t for t in self.tools.values() if keep(t)]

    def get(self, tool_id: str) -> Tool:
        return self.tools[tool_id]

    def abs_path(self, tool_id: str) -> Path:
        return self.root / self.tools[tool_id].path

    def register(self, tool: Tool) -> Tool:
        """Add/replace a catalog entry (metadata). Use add_file to also import a binary."""
        self.tools[tool.id] = tool
        self.save()
        return tool

    # --- research/65 §B: the dependency / Technical-Environment resolver -------
    # The flat catalog + Tool.relations form a graph. These read-only methods turn a
    # format need into the runnable stack (PREMIS Technical Environment) the AI analyst
    # asks for: "this work needs application/x-director on windows-xp" -> the binary, its
    # dependency chain, its conservation quirks, and its alternatives.

    def reads(
        self, *, mime: str | None = None, ext: str | None = None, puid: str | None = None
    ) -> builtins.list[Tool]:
        """Tools that can READ a format — via handles_mime/handles_ext OR a reads_format
        relation (PRONOM PUID or MIME). Any provided key that matches counts."""

        def hit(t: Tool) -> bool:
            if mime and mime in t.handles_mime:
                return True
            if ext and ext in t.handles_ext:
                return True
            for r in t.relations:
                if r.get("rel") != "reads_format":
                    continue
                if puid and r.get("target") == puid:
                    return True
                if mime and (r.get("mime") == mime or r.get("target") == mime):
                    return True
            return False

        return [t for t in self.tools.values() if hit(t)]

    def technical_environment(self, tool_id: str) -> dict:
        """The runnable stack for one tool: its OS band, the recursive depends_on chain,
        conservation quirks (network-bootstrap / known-CVE / notes), and alternatives.
        A dependency `target_id` that isn't in the catalog is still listed (a known gap)."""
        t = self.tools[tool_id]  # KeyError -> 404 at the API layer
        deps: builtins.list[dict] = []
        seen: set[str] = {tool_id}

        def walk(tid: str) -> None:
            node = self.tools.get(tid)
            if node is None:
                return
            for r in node.relations:
                if r.get("rel") != "depends_on":
                    continue
                dep = r.get("target_id") or r.get("target")
                if not dep or dep in seen:
                    continue
                seen.add(dep)
                deps.append({"id": dep, "note": r.get("note", ""), "in_catalog": dep in self.tools})
                walk(dep)

        walk(tool_id)
        quirks: builtins.list[str] = []
        if t.network_required or t.install_mode == "network-bootstrap":
            quirks.append(
                "network-bootstrap installer — vendor URLs may be dead; host payload locally"
            )
        if t.known_cves:
            quirks.append(f"keep the guest OFFLINE — {len(t.known_cves)} known unpatched CVE(s)")
        alternatives = [
            (r.get("target_id") or r.get("target"))
            for r in t.relations
            if r.get("rel") == "alternative_to"
        ]
        return {
            "tool": tool_id,
            "name": t.name,
            "present": t.present,
            "os_compat": list(t.os_compat),
            "install": t.install_mode,
            "depends_on": deps,
            "alternatives": [a for a in alternatives if a],
            "quirks": quirks,
        }

    def resolve(
        self,
        *,
        mime: str | None = None,
        ext: str | None = None,
        puid: str | None = None,
        os: str | None = None,
    ) -> builtins.list[dict]:
        """AI entrypoint: a format (+ optional target OS) -> ranked runnable stacks.

        Ranks OS-matching first, then present-on-disk, then most-complete. Never filters
        the OS mismatch OUT (returns it ranked lower) so the analyst still sees a tool
        that reads the format even if the era isn't perfect."""
        cands = self.reads(mime=mime, ext=ext, puid=puid)
        cands.sort(
            key=lambda t: (
                not t.matches_os(os) if os else False,
                not t.present,
                -t.completeness(),
            )
        )
        return [
            {**self.technical_environment(t.id), "os_match": t.matches_os(os) if os else None}
            for t in cands
        ]

    # --- CRUD on existing entries ----------------------------------------
    # Editable metadata fields (everything except the file-derived identity:
    # id/path/size/sha256 are set by add_file and must not drift from the binary).
    EDITABLE = (
        "name",
        "os",
        "runtime",
        "version",
        "variant",
        "kind",
        "source",
        "license",
        "stage",
        "notes",
        "present",
        "os_compat",
        # provenance (file-identity fields id/path/size/sha256 stay locked)
        "source_page",
        "download_url",
        "found_by",
        "found_via",
        "verified",
        "verify_evidence",
        # enrichment first-slice (research/65)
        "category",
        "family",
        "slug",
        "tool_class",
        "vendor",
        "browser_integration",
        "install_mode",
        "scan_status",
        "network_required",
        "description_short",
        "enrichment_status",
        "handles_mime",
        "handles_ext",
        "implements_spec",
        "requires_browser",
        "known_cves",
        "relations",
    )
    # Editable fields whose value is a list (coerced on write).
    LIST_FIELDS = frozenset(
        {
            "os_compat",
            "handles_mime",
            "handles_ext",
            "implements_spec",
            "requires_browser",
            "known_cves",
            "relations",
        }
    )

    def update(self, tool_id: str, *, by: str = "?", **fields) -> Tool:
        """Patch an existing catalog entry's metadata (not its file/sha).

        Only EDITABLE fields are applied; unknown/identity keys are ignored so a
        caller can't silently corrupt the path/sha binding. Records an `edited`
        provenance event naming the changed fields. Raises KeyError if unknown.
        """
        t = self.tools[tool_id]  # KeyError -> 404 at the API layer
        changed: list[str] = []
        for k, v in fields.items():
            if v is None or k not in self.EDITABLE:
                continue
            new = list(v) if k in self.LIST_FIELDS else v
            if k == "category":
                new = coerce_category(v)  # category is a scalar str field, not a LIST_FIELD
            if getattr(t, k) != new:
                setattr(t, k, new)
                changed.append(k)
        if "verified" in changed and t.verified:
            t.verified_at = _now()
        if changed:
            t.log_event("edited", by=by, note=", ".join(changed))
        self.save()
        return t

    def add_event(
        self, tool_id: str, action: str, *, by: str = "?", note: str = "", **extra
    ) -> Tool:
        """Append a free-form provenance event (e.g. a re-verification, a note)."""
        t = self.tools[tool_id]  # KeyError -> 404 at the API layer
        t.log_event(action, by=by, note=note, **extra)
        self.save()
        return t

    def delete(self, tool_id: str, *, remove_file: bool = False) -> Tool:
        """Drop a catalog entry. With remove_file, also unlink the binary on disk
        (best-effort; the catalog is the source of truth and is always updated).
        Returns the removed Tool. Raises KeyError if unknown."""
        t = self.tools.pop(tool_id)  # KeyError -> 404 at the API layer
        if remove_file and t.path:
            with contextlib.suppress(OSError):
                (self.root / t.path).unlink(missing_ok=True)
        self.save()
        return t

    def add_file(
        self,
        src: str | Path,
        *,
        id: str,
        name: str,
        os: str,
        runtime: str,
        version: str,
        variant: str = "",
        kind: str = "installer",
        source: str = "",
        license: str = "",
        stage: str = "art",
        notes: str = "",
        os_compat: builtins.list[str] | None = None,
        move: bool = False,
        by: str = "?",
        source_page: str = "",
        download_url: str = "",
        found_by: str = "",
        found_via: str = "",
        verified: bool = False,
        verify_evidence: str = "",
        extra: dict | None = None,
    ) -> Tool:
        """Import a binary into the box (verified by sha256), write SOURCE.md, catalog it.

        Provenance (`source_page`/`download_url`/`found_by`/`found_via`/`verified`/
        `verify_evidence`) and `by` (the operator) are recorded on the entry and seed
        the tool's history with a `catalogued` event.
        """
        src = Path(src)
        dest_dir = self.root / os / runtime / version
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest = dest_dir / src.name
        (shutil.move if move else shutil.copy2)(str(src), str(dest))
        sha = _sha256(dest)
        (dest_dir / "SHA256SUMS").open("a").write(f"{sha}  {src.name}\n")
        (dest_dir / "SOURCE.md").write_text(
            f"# {name}\n- source page: {source_page or source}\n- download: {download_url}\n"
            f"- found by: {found_by} (via {found_via})\n- licence: {license}\n"
            f"- sha256: {sha}\n- file: {src.name}\n"
        )
        now = _now()
        t = Tool(
            id=id,
            name=name,
            os=os,
            runtime=runtime,
            version=version,
            variant=variant,
            kind=kind,
            path=str(dest.relative_to(self.root)),
            size=dest.stat().st_size,
            sha256=sha,
            source=source,
            license=license,
            stage=stage,
            notes=notes,
            present=True,
            os_compat=list(os_compat or []),
            source_page=source_page,
            download_url=download_url,
            found_by=found_by,
            found_via=found_via,
            verified=verified,
            verify_evidence=verify_evidence,
            verified_at=now if verified else "",
            added_by=by,
            added_at=now,
        )
        # Seed enrichment metadata (category/handles/…) if the caller supplied it.
        for k, v in (extra or {}).items():
            if v is None or k not in self.EDITABLE:
                continue
            setattr(t, k, list(v) if k in self.LIST_FIELDS else v)
        # Canonicalize the taxonomy: map any legacy category to a function, and default
        # the id-axis `family` to the runtime line when the caller didn't set it.
        t.category = coerce_category(t.category)
        if not t.family:
            t.family = t.runtime
        t.log_event(
            "catalogued",
            by=by,
            note=f"{src.name} ({t.size} bytes, sha256 {sha[:12]}…)",
            download_url=download_url,
            found_by=found_by,
        )
        return self.register(t)
