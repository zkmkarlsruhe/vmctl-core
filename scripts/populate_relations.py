#!/usr/bin/env python3
"""Populate the research/65 §B relationship graph onto the tools-box catalog.

Additive + idempotent: stamps `relations[]` edges (alternative_to / followed_by /
depends_on / reads_format) onto known fleet entries, de-duping against what's already
there. Software<->software edges use canonical target_id; format edges (reads_format)
use a PRONOM PUID in `target` + the MIME in `mime`. A depends_on target that isn't a
catalog tool (Director Xtras, Authorware webplr07) is still recorded — it's a known gap
the resolver surfaces. Source ids not in the catalog are skipped with a warning (so this
can run before/after a browser batch merges).

Usage: python scripts/populate_relations.py CATALOG.json [--write]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

# tool_id -> list of relation dicts to ensure present. Version CHAINS are expressed once
# as followed_by (newer is the successor); the reverse `replaces` is left implicit.
RELATIONS: dict[str, list[dict]] = {
    # --- Flash: three variants of one runtime; reads SWF (PRONOM fmt/507) ---
    "runtime.flash.player-sa.32-0-0-465": [
        {
            "rel": "alternative_to",
            "target_id": "runtime.flash.player-npapi.32-0-0-465",
            "note": "browser plugin vs standalone projector",
        },
        {"rel": "alternative_to", "target_id": "runtime.flash.player-activex.32-0-0-465"},
        {
            "rel": "reads_format",
            "target": "fmt/507",
            "mime": "application/x-shockwave-flash",
            "confidence": "high",
        },
    ],
    "runtime.flash.player-npapi.32-0-0-465": [
        {
            "rel": "alternative_to",
            "target_id": "runtime.flash.player-activex.32-0-0-465",
            "note": "NPAPI (Firefox/Netscape) vs ActiveX (IE)",
        },
        {
            "rel": "reads_format",
            "target": "fmt/507",
            "mime": "application/x-shockwave-flash",
            "confidence": "high",
        },
    ],
    "runtime.flash.player-activex.32-0-0-465": [
        {
            "rel": "reads_format",
            "target": "fmt/507",
            "mime": "application/x-shockwave-flash",
            "confidence": "high",
        },
    ],
    # --- Director: reads DCR/DIR; DEPENDS ON its Xtras (not a catalog tool) ---
    "runtime.director.shockwave-player.12-3-5-205": [
        {
            "rel": "depends_on",
            "target": "director-xtras",
            "note": "Xtras/ (IML32/DIRAPI/custom) must sit beside the projector or in the system Xtras path; missing Xtras = broken playback",
        },
        {
            "rel": "reads_format",
            "target": "x-fmt/396",
            "mime": "application/x-director",
            "confidence": "medium",
        },
    ],
    # --- Authorware: network-bootstrap installer depends on the webplr07 runtime tree ---
    "runtime.authorware.web-player.7-02": [
        {
            "rel": "depends_on",
            "target": "authorware-webplr07",
            "note": "211KB stub pulls webplr07/*.x32 from the dead download.macromedia.com; host the full webplr07/ tree locally (Wayback)",
        },
    ],
    # --- RealPlayer: the catalogued binary is an ALTERNATIVE re-implementation ---
    "runtime.realplayer.real-alternative.2-0-2": [
        {
            "rel": "alternative_to",
            "target": "RealPlayer",
            "note": "Real Alternative = MPC + RealMedia plugin, no account/adware; substitutes the official RealPlayer",
        },
        {
            "rel": "reads_format",
            "target": "fmt/199",
            "mime": "application/vnd.rn-realmedia",
            "confidence": "medium",
        },
    ],
    # --- VRML: Cortona and Cosmo are interchangeable VRML97 viewers ---
    "runtime.vrml.cortona-client.5-1-0-167": [
        {
            "rel": "alternative_to",
            "target_id": "runtime.vrml.cosmo-player.2-1-1",
            "note": "both VRML97 browser plugins",
        },
    ],
    # --- QuickTime: reads MOV ---
    "runtime.quicktime.player-win.7-7-9": [
        {
            "rel": "reads_format",
            "target": "x-fmt/384",
            "mime": "video/quicktime",
            "confidence": "medium",
        },
    ],
    # --- .NET Framework: the era chain 1.1 -> 2.0 -> 3.5 -> 4.0 -> 4.8 ---
    "redist.dotnet.framework.1-1": [
        {"rel": "followed_by", "target_id": "redist.dotnet.framework.2-0-sp2"}
    ],
    "redist.dotnet.framework.2-0-sp2": [
        {
            "rel": "followed_by",
            "target_id": "redist.dotnet.framework.3-5-sp1",
            "note": "3.5 bundles the 2.0/3.0 CLR side-by-side",
        }
    ],
    "redist.dotnet.framework.3-5-sp1": [
        {
            "rel": "followed_by",
            "target_id": "redist.dotnet.framework.4-0",
            "note": "4.x is a NEW CLR, side-by-side with 3.5 — not a replacement",
        }
    ],
    "redist.dotnet.framework.4-0": [
        {
            "rel": "followed_by",
            "target_id": "redist.dotnet.framework.4-8",
            "note": "4.x are in-place updates of one CLR",
        }
    ],
    # --- JRE: the class-era chain ---
    "runtime.java.jre.1-4-2-19": [
        {"rel": "followed_by", "target_id": "runtime.java.jre.1-5-0-22"},
        {
            "rel": "reads_format",
            "target": "x-fmt/412",
            "mime": "application/java-archive",
            "confidence": "medium",
        },
    ],
    "runtime.java.jre.1-5-0-22": [{"rel": "followed_by", "target_id": "runtime.java.jre.6u45"}],
    "runtime.java.jre.6u45": [{"rel": "followed_by", "target_id": "runtime.java.jre.7u80"}],
    "runtime.java.jre.7u80": [{"rel": "followed_by", "target_id": "runtime.java.jre.8u261"}],
    # --- Unpackers: unar cli/app are one project; both alt to StuffIt for .sit ---
    "unpacker.unar.cli.1-8-1": [{"rel": "followed_by", "target_id": "unpacker.unar.cli.1-10-1"}],
    "unpacker.unar.cli.1-10-1": [
        {
            "rel": "alternative_to",
            "target_id": "unpacker.unar.app.4-0-0",
            "note": "CLI vs GUI, same codebase",
        },
        {
            "rel": "alternative_to",
            "target_id": "unpacker.stuffit.expander.5-5",
            "note": "both expand .sit preserving forks",
        },
    ],
    # --- Firefox ESR era chain (version carries the `esr` channel suffix) ---
    "runtime.firefox.esr.52-9-0esr": [
        {
            "rel": "followed_by",
            "target_id": "runtime.firefox.esr.68-12-0esr",
            "note": "52.9 = last XUL/legacy add-ons; 68 = WebExtensions-only",
        }
    ],
    "runtime.firefox.esr.68-12-0esr": [
        {"rel": "followed_by", "target_id": "runtime.firefox.esr.115-14-0esr"}
    ],
    "runtime.firefox.esr.115-14-0esr": [
        {"rel": "followed_by", "target_id": "runtime.firefox.esr.128-14-0esr"}
    ],
    # --- Chromium/Chrome era chain (min_chrome 51 -> 93 -> 122) ---
    "runtime.chromium.win.51-0-2704-0": [
        {"rel": "followed_by", "target_id": "runtime.chromium.win.93-0-4577-0"}
    ],
    "runtime.chromium.win.93-0-4577-0": [
        {"rel": "followed_by", "target_id": "runtime.chrome.win.122-0-6261-128"}
    ],
    # --- userscript managers are interchangeable (.user.js runners) ---
    "runtime.userscript.tampermonkey.5-5-0": [
        {
            "rel": "alternative_to",
            "target_id": "runtime.userscript.violentmonkey.2-44-0",
            "note": "both run .user.js; Tampermonkey freeware, Violentmonkey MIT",
        },
        {
            "rel": "alternative_to",
            "target_id": "runtime.userscript.greasemonkey.4-14",
            "note": "Greasemonkey = the original Firefox userscript engine",
        },
    ],
}


def _same_edge(a: dict, b: dict) -> bool:
    return (
        a.get("rel") == b.get("rel")
        and a.get("target_id") == b.get("target_id")
        and a.get("target") == b.get("target")
    )


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("catalog", type=Path)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()

    data = json.loads(args.catalog.read_text())
    by_id = {t["id"]: t for t in data.get("tools", [])}
    added = skipped = 0
    for tid, edges in RELATIONS.items():
        t = by_id.get(tid)
        if t is None:
            print(f"  ~ skip (not in catalog yet): {tid}")
            skipped += 1
            continue
        rels = t.setdefault("relations", [])
        for e in edges:
            if any(_same_edge(e, r) for r in rels):
                continue
            rels.append(e)
            added += 1
            tgt = e.get("target_id") or e.get("target")
            print(f"  + {tid}  --{e['rel']}-->  {tgt}")

    print(f"\nadded {added} edges; {skipped} source ids not present yet")
    if args.write:
        args.catalog.write_text(json.dumps(data, indent=2))
        print(f"wrote {args.catalog}")
    else:
        print("(dry run — pass --write to apply)")


if __name__ == "__main__":
    main()
