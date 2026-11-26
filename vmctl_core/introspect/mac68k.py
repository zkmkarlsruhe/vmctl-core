"""Classic Mac OS low memory in MAME's host-endian 32-bit RAM words."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from .memory import Memory, Unreadable

# Inside Macintosh: Operating System Utilities, Low-Memory Global Variables.
SYS_VERSION, TICKS, ROM_BASE, CUR_AP_NAME = 0x15A, 0x16A, 0x2AE, 0x910
ROM_MIN, ROM_MAX = 0x40800000, 0x42000000
APP_NAME_LIMIT = 32


@dataclass
class MacSample:
    ticks: int | None = None
    cur_app: str | None = None
    sysversion: str | None = None
    status: str = "ok"
    error: str | None = None


class MacView:
    def __init__(self, mem: Memory, ram_bytes: int):
        self.mem = mem
        self.ram_bytes = ram_bytes
        self.base: int | None = None

    def attach(self) -> None:
        self.base = None
        for lo, hi in self.mem.maps:
            if self.ram_bytes <= hi - lo < self.ram_bytes + (1 << 20):
                for offset in range(0, 0x1000, 16):
                    if lo + offset + self.ram_bytes > hi:
                        break
                    self.base = lo + offset
                    try:
                        self._app_name()
                        rom = int.from_bytes(self.get(ROM_BASE, 4), "big")
                        if ROM_MIN <= rom < ROM_MAX:
                            return
                    except PermissionError:
                        raise
                    except OSError:
                        continue
        self.base = None
        raise Unreadable("Mac RAM not found")

    def get(self, addr: int, size: int) -> bytes:
        lo, hi = addr & ~3, (addr + size + 3) & ~3
        if self.base is None or addr < 0 or size < 0 or hi > self.ram_bytes:
            raise Unreadable(f"Mac RAM range {addr:#x}+{size:#x} is unreadable")
        raw = self.mem.read(self.base + lo, hi - lo)
        if len(raw) != hi - lo:
            raise Unreadable("short Mac RAM read")
        if sys.byteorder == "little":
            raw = b"".join(raw[i : i + 4][::-1] for i in range(0, len(raw), 4))
        return raw[addr - lo : addr - lo + size]

    def _app_name(self) -> str:
        size = self.get(CUR_AP_NAME, 1)[0]
        if not 0 < size < APP_NAME_LIMIT:
            raise Unreadable("invalid CurApName length")
        raw = self.get(CUR_AP_NAME + 1, size)
        if not all(31 < char < 255 for char in raw):
            raise Unreadable("CurApName is not printable")
        return raw.decode("mac_roman")

    def sample(self) -> MacSample:
        try:
            return MacSample(
                ticks=int.from_bytes(self.get(TICKS, 4), "big"),
                cur_app=self._app_name(),
                sysversion=hex(int.from_bytes(self.get(SYS_VERSION, 2), "big")),
            )
        except PermissionError:
            raise
        except OSError as exc:
            return MacSample(status="unreadable", error=str(exc))
