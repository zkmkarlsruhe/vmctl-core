"""Atomic file writes for the source-of-truth JSON registries.

catalog.json / registry.json are each the single source of truth for the tools
library / project registry; a plain truncating write that is interrupted (crash,
OOM-kill, full disk) leaves a half-written file that fails to parse on the next
load(), bricking the whole library. Write to a same-dir temp, fsync it, then
atomically rename over the target so a reader only ever sees the old or the new
file, never a torn one.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path


def write_text_atomic(path: str | Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write ``text`` to ``path`` atomically (same-dir temp + fsync + os.replace)."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=f".{p.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, p)  # atomic on the same filesystem
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
