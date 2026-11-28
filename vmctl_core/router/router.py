"""The router: match a Flow against plugin claims, walk the rung ladder, detect conflicts.

Kept free of controller/proxy specifics (codex's core/adapter split) — it decides WHICH rung
gets a flow; the rung does the work. Same first-non-DECLINE semantics the plugin registry and
the wbc chain already use, plus the Terminal outcome (owned-but-absent stops the ladder).
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field

from vmctl_core.plugins.spec import PluginClaim
from vmctl_core.router.types import DECLINE, Flow, Outcome, Rung


def claim_matches(claim: PluginClaim, flow: Flow) -> bool:
    """Does this plugin claim admit this flow? host (fnmatch) + port + protocol + method + path."""
    if not fnmatch.fnmatch(flow.dst_host, claim.host):
        return False
    if claim.ports and flow.dst_port not in claim.ports:
        return False
    if claim.protocols and flow.proto not in claim.protocols:
        return False
    if (
        claim.methods
        and flow.method is not None
        and flow.method.upper() not in {m.upper() for m in claim.methods}
    ):
        return False
    return not (
        claim.paths
        and flow.path is not None
        and not any(fnmatch.fnmatch(flow.path, p) for p in claim.paths)
    )


def _sets_overlap(a: list, b: list) -> bool:
    """Constraint-set overlap with claim_matches semantics: an EMPTY list means "any"
    (matching claim_matches, which skips an empty constraint), so it overlaps anything;
    two non-empty lists overlap iff their sets intersect."""
    if not a or not b:
        return True
    return bool(set(a) & set(b))


def _methods_overlap(a: list[str], b: list[str]) -> bool:
    """Method overlap, case-insensitive (claim_matches upper-cases both sides); empty = any."""
    if not a or not b:
        return True
    return bool({m.upper() for m in a} & {m.upper() for m in b})


def _paths_overlap(a: list[str], b: list[str]) -> bool:
    """Approximate fnmatch-pattern overlap the same way host overlap is judged: empty = any
    (claim_matches skips an empty path list), else two patterns overlap when equal or either
    fnmatches the other's literal — exact paths (the common case) are caught precisely, so
    disjoint path-split claims (``/api/*`` vs ``/ui/*``) don't false-conflict."""
    if not a or not b:
        return True
    return any(
        pa == pb or fnmatch.fnmatch(pb, pa) or fnmatch.fnmatch(pa, pb) for pa in a for pb in b
    )


def claims_overlap(a: PluginClaim, b: PluginClaim) -> bool:
    """Two claims collide if their hosts can name a common target AND their port, protocol,
    method and path constraints can ALL admit a common flow. Consistent with claim_matches:
    an empty ports/protocols/methods/paths list means "any" (so it overlaps anything), and
    disjoint method- or path-split claims on the same host do NOT conflict. Host-pattern
    overlap is approximated by equality or either fnmatching the other's literal — exact
    hosts (the common case) are caught precisely."""
    ha, hb = a.host, b.host
    host_overlap = ha == hb or fnmatch.fnmatch(hb, ha) or fnmatch.fnmatch(ha, hb)
    if not host_overlap:
        return False
    if not _sets_overlap(a.ports, b.ports):
        return False
    if not _sets_overlap(a.protocols, b.protocols):
        return False
    if not _methods_overlap(a.methods, b.methods):
        return False
    return _paths_overlap(a.paths, b.paths)


def detect_claim_conflicts(
    claims_by_plugin: dict[str, list[PluginClaim]],
) -> list[tuple[str, str, str]]:
    """Return (plugin_a, plugin_b, host) for every overlapping claim pair across plugins.
    The router build fails hard on a non-empty result (vs the load-time WARNING in P1)."""
    conflicts: list[tuple[str, str, str]] = []
    items = list(claims_by_plugin.items())
    for i in range(len(items)):
        pid_a, cs_a = items[i]
        for j in range(i + 1, len(items)):
            pid_b, cs_b = items[j]
            for ca in cs_a:
                for cb in cs_b:
                    if claims_overlap(ca, cb):
                        conflicts.append((pid_a, pid_b, ca.host))
    return conflicts


class ClaimConflictError(ValueError):
    """Two plugins claim overlapping traffic — the router refuses to build ambiguously."""


@dataclass
class Router:
    """An ordered ladder of rungs. Rung 0 should be the plugin (first refusal)."""

    rungs: list[Rung] = field(default_factory=list)

    def route(self, flow: Flow) -> Outcome | None:
        """Offer the flow to each rung in order; the first that does not DECLINE wins
        (Handled or Terminal both stop). Returns None on a full-ladder miss.

        A rung that raises is NOT swallowed — a crashed plugin surfaces to the caller
        (which logs + returns a 502) rather than silently falling through to archive/live
        content (the eval's silent-fallthrough gap)."""
        for rung in self.rungs:
            if not rung.can_handle(flow):
                continue
            out = rung.handle(flow)
            if out is DECLINE:
                continue
            return out
        return None
