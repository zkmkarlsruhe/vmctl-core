"""Build ISO images ("fakeCD") to hand files to a guest over its CD-ROM.

A CD-ROM is the one file-share every legacy guest reads with no extra drivers, so
this is how we get the virtio-win driver disc — or any uploaded files — into
Windows XP/9x, Mac OS 9, old Linux. Read-only / host→guest.
"""

from __future__ import annotations

import subprocess
from pathlib import Path


def build_iso(
    src_dir: str | Path,
    out_path: str | Path,
    label: str = "VMCTL",
    extra: dict[str, str | Path] | None = None,
) -> Path:
    """Pack a directory into an ISO9660 (Joliet + Rock Ridge) image.

    ``extra`` grafts additional directory trees onto the disc under named
    subdirs (mkisofs graft points), e.g. ``{"artwork": <drive>/artwork}`` puts
    that tree at ``/artwork`` on the CD next to ``src_dir``'s files at ``/``.
    """
    src, out = Path(src_dir), Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    label = (label or "VMCTL")[:32]
    srcs = [str(src)]
    if extra:
        srcs = ["-graft-points", str(src)] + [
            f"{name}/={Path(p)}" for name, p in sorted(extra.items())
        ]
    candidates = [
        ["xorriso", "-as", "mkisofs", "-J", "-r", "-V", label, "-o", str(out), *srcs],
        ["genisoimage", "-J", "-r", "-V", label, "-o", str(out), *srcs],
    ]
    last = ""
    for cmd in candidates:
        try:
            p = subprocess.run(cmd, capture_output=True, text=True)
        except FileNotFoundError:
            continue
        if p.returncode == 0:
            return out
        last = p.stderr.strip()
    raise RuntimeError(f"could not build ISO (need xorriso or genisoimage): {last}")
