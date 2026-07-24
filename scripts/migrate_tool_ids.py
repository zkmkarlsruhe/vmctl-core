#!/usr/bin/env python3
"""Migrate a tools-box catalog.json to the canonical id + category taxonomy (2026-07).

For every tool it:
  * coerces the legacy free-text `category` to a canonical FUNCTION (runtime/redist/
    driver/unpacker/provisioning) via LEGACY_CATEGORY_MAP,
  * defaults the id-axis `family` to the `runtime` line when unset,
  * fills `slug` from SLUG_MAP (known pre-refactor tools) or by parsing an already-
    canonical id, and
  * rewrites `id` to canonical_tool_id(category, family, slug, version, variant),
    recording the old id in the tool's history so nothing silently loses its identity.

Optionally ingests staged catalog fragments from an --inbox dir (one Tool JSON per
file) BEFORE normalizing, so "source a tool -> drop a fragment -> merge" is one pass.

Usage:
    python scripts/migrate_tool_ids.py CATALOG.json [--inbox DIR] [--write]
Without --write it is a dry run (prints the id remapping + any collisions, changes
nothing).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Import the taxonomy from the package this script ships with.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vmctl_core.tools import (
    CATEGORIES,
    canonical_tool_id,
    coerce_category,
)

# Explicit slug for the pre-refactor tools whose old ids don't encode a clean slug.
# Keyed by the OLD id. family falls back to the `runtime` field; here we only pin slug.
SLUG_MAP: dict[str, str] = {
    "authorware-web-player-2004": "web-player",
    "silverlight-5.1.50918-x86": "player",
    "adobe-svg-viewer-3.03": "adobe",
    "real-alternative-2.0.2": "real-alternative",
    "cortona-vrml-client-5.1": "cortona-client",
    "cosmo-player-2.1.1": "cosmo-player",
    "beatnik-player-2.2.1.100": "player",
}


def _slug_from_canonical(tool_id: str, family: str) -> str:
    """If an id is already canonical (cat.family.slug.ver[.variant]), recover its slug."""
    parts = tool_id.split(".")
    if len(parts) >= 4 and parts[0] in CATEGORIES:
        return parts[2]
    return ""


def normalize(tool: dict) -> tuple[str, str]:
    """Return (old_id, new_id) after mutating `tool` in place to the canonical taxonomy."""
    old_id = tool["id"]
    tool["category"] = coerce_category(tool.get("category", ""))
    if not tool.get("family"):
        tool["family"] = tool.get("runtime", "")
    if not tool.get("slug"):
        tool["slug"] = SLUG_MAP.get(old_id) or _slug_from_canonical(old_id, tool["family"])
    if not tool["slug"]:
        raise SystemExit(
            f"  ! no slug for {old_id!r} — add it to SLUG_MAP (id not canonical either)"
        )
    new_id = canonical_tool_id(tool["category"], tool["family"], tool["slug"], tool["version"])
    if new_id != old_id:
        tool.setdefault("history", []).append(
            {
                "ts": "",
                "who": "migrate_tool_ids",
                "action": "recanonicalized",
                "note": f"{old_id} -> {new_id}",
            }
        )
        tool["id"] = new_id
    return old_id, new_id


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("catalog", type=Path)
    ap.add_argument(
        "--inbox", type=Path, default=None, help="dir of staged Tool JSON fragments to merge first"
    )
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    data = json.loads(args.catalog.read_text())
    tools: list[dict] = data.get("tools", [])
    by_id = {t["id"]: t for t in tools}

    if args.inbox and args.inbox.is_dir():
        for frag in sorted(args.inbox.glob("*.json")):
            t = json.loads(frag.read_text())
            print(f"+ inbox {frag.name}: {t['id']}")
            by_id[t["id"]] = t  # add/replace
    tools = list(by_id.values())

    seen: dict[str, str] = {}
    out: list[dict] = []
    for t in tools:
        old_id, new_id = normalize(t)
        flag = "" if old_id == new_id else f"  (was: {old_id})"
        if new_id in seen:
            print(f"  !! COLLISION {new_id} <- {old_id} and {seen[new_id]}")
        seen[new_id] = old_id
        print(f"  {t['category']:12} {new_id}{flag}")
        out.append(t)

    print(f"\n{len(out)} tools; categories present: {sorted({t['category'] for t in out})}")
    non_canon = [t["category"] for t in out if t["category"] not in CATEGORIES]
    if non_canon:
        print(f"  ! non-canonical categories still present: {sorted(set(non_canon))}")

    if args.write:
        data["tools"] = out
        args.catalog.write_text(json.dumps(data, indent=2))
        print(f"\nwrote {args.catalog}")
    else:
        print("\n(dry run — pass --write to apply)")


if __name__ == "__main__":
    main()
