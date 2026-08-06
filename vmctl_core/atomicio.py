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
        # mkstemp forces 0600; restore the 0644 a plain write would have produced so a drive.yaml
        # written by one uid (the autopsy container as root) stays readable by the other controllers
        # sharing the drive (host-side rvmc as a different user). No secrets live in these files.
        os.chmod(tmp, 0o644)
        os.replace(tmp, p)  # atomic on the same filesystem
        # fsync the PARENT directory too: os.replace makes the new contents visible, but the
        # directory entry (the rename itself) isn't durable until the dir is fsynced. Without this a
        # hard crash right after replace can lose the rename, leaving the old file — or on some
        # filesystems a zero-length entry. Best-effort: some platforms can't fsync a directory fd.
        with contextlib.suppress(OSError):
            dir_fd = os.open(str(p.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise
