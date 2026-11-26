"""Bounded, read-only process memory access and an in-memory test implementation."""

from __future__ import annotations

import os
from pathlib import Path
from types import TracebackType

SCAN_BYTES = 16 << 20
_SKIP = ("/lib/", "/usr/", "/dev/", "[v")


class Unreadable(OSError):
    """A guest structure is missing, torn, or outside readable memory."""


class Memory:
    maps: list[tuple[int, int]]

    def read(self, addr: int, size: int) -> bytes:
        raise NotImplementedError

    def contains(self, addr: int, size: int) -> bool:
        return size >= 0 and any(lo <= addr and addr + size <= hi for lo, hi in self.maps)

    def find(self, pattern: bytes, limit: int = 200) -> list[int]:
        if not pattern or limit <= 0:
            return []
        hits: list[int] = []
        for lo, hi in self.maps:
            for pos in range(lo, hi, SCAN_BYTES):
                try:
                    chunk = self.read(pos, min(SCAN_BYTES + len(pattern) - 1, hi - pos))
                except PermissionError:
                    raise
                except OSError:
                    break
                offset = chunk.find(pattern)
                while 0 <= offset < SCAN_BYTES:
                    hits.append(pos + offset)
                    if len(hits) >= limit:
                        return hits
                    offset = chunk.find(pattern, offset + 1)
        return hits


class ProcMemory(Memory):
    def __init__(self, pid: int):
        self.pid = pid
        self.maps = []
        for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
            fields = line.split(maxsplit=5)
            path = fields[5] if len(fields) > 5 else ""
            if "r" in fields[1] and not path.startswith(_SKIP):
                lo, hi = (int(part, 16) for part in fields[0].split("-"))
                self.maps.append((lo, hi))
        # Linux proc_pid_stat(5): field 22 is starttime; comm may contain spaces or ')'.
        stat = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        self.identity = (pid, stat[19])
        self.fd = os.open(f"/proc/{pid}/mem", os.O_RDONLY)

    def read(self, addr: int, size: int) -> bytes:
        if not self.contains(addr, size):
            raise Unreadable(f"host range {addr:#x}+{size:#x} is unreadable")
        raw = os.pread(self.fd, size, addr)
        if len(raw) != size:
            raise Unreadable(f"short read at {addr:#x}: {len(raw)}/{size}")
        return raw

    def close(self) -> None:
        if self.fd >= 0:
            os.close(self.fd)
            self.fd = -1

    def __enter__(self) -> ProcMemory:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class FakeMemory(Memory):
    def __init__(self, ranges: dict[tuple[int, int], bytes]):
        if any(hi - lo != len(raw) for (lo, hi), raw in ranges.items()):
            raise ValueError("host range size must match its bytes")
        self.ranges = ranges
        self.maps = sorted(ranges)

    def read(self, addr: int, size: int) -> bytes:
        for (lo, hi), raw in self.ranges.items():
            if size >= 0 and lo <= addr and addr + size <= hi:
                return bytes(raw[addr - lo : addr - lo + size])
        raise Unreadable(f"host range {addr:#x}+{size:#x} is unreadable")
