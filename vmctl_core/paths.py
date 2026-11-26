"""One definition of "this string may be used as a single path segment".

The same three-line check had grown a copy per module — ``tools._safe_segment`` for a tool's
os/runtime/version, ``drive._confine_to_analysis`` for a network-config filename, and one in the
exhibition controller's catalog — while the exhibition IMPORTER, which joins a value straight out
of an untrusted bundle to a directory it later ``rmtree``s, had none at all. A guard that exists
in three places and is missing in the fourth is the shape of a bug, so it lives here now.
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["safe_segment"]


def safe_segment(seg: str, *, field: str) -> str:
    """Return ``seg`` if it is a bare path segment, else raise ``ValueError``.

    Bare means: non-empty, not ``.`` or ``..``, and unchanged by ``Path(seg).name`` — which
    rules out separators, absolute paths and traversal. Use it on every value that is
    interpolated into a filesystem path and comes from outside the process.
    """
    if not seg or seg in (".", "..") or seg != Path(seg).name:
        raise ValueError(f"{field} must be a bare path segment, got {seg!r}")
    return seg
