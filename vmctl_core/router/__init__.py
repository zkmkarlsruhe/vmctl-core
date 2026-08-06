"""Hosting-agnostic guest-egress router core (shared by rvmctl + evmctl).

The plugin is rung-0 (first refusal); wbc/pywb/live are lower rungs. See ``types`` for the
Flow/Rung/outcome primitives and ``router`` for the ladder walk + claim conflict detection.
"""

from __future__ import annotations

from .router import (
    ClaimConflictError,
    Router,
    claim_matches,
    claims_overlap,
    detect_claim_conflicts,
)
from .types import DECLINE, Flow, Handled, Outcome, Rung, Terminal

__all__ = [
    "DECLINE",
    "ClaimConflictError",
    "Flow",
    "Handled",
    "Outcome",
    "Router",
    "Rung",
    "Terminal",
    "claim_matches",
    "claims_overlap",
    "detect_claim_conflicts",
]
