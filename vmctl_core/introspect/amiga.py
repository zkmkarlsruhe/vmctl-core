"""AmigaOS Exec/task view, discovered through Kickstart and Exec's MemList."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from .memory import Memory, Unreadable

# Amiga NDK 3.1: exec/nodes.h, exec/lists.h (byte offsets, big endian).
LN_SUCC, LN_PRED, LN_TYPE, LN_PRI, LN_NAME = 0, 4, 8, 9, 10
LH_TAIL = 4
NT_TASK, NT_LIBRARY, NT_MEMORY, NT_PROCESS = 1, 9, 10, 13
# Amiga NDK 3.1: exec/execbase.h.
CHK_BASE = 38
THIS_TASK, IDLE_COUNT, DISP_COUNT = 276, 280, 284
MEM_LIST, DEVICE_LIST, LIB_LIST, PORT_LIST, TASK_READY, TASK_WAIT = 322, 350, 378, 392, 406, 420
VBLANK_FREQUENCY = 0x212
EXEC_SIZE = 0x220
# Amiga NDK 3.1: exec/memory.h, struct MemHeader.
MH_LOWER, MH_UPPER, MH_FREE, MH_SIZE = 20, 24, 28, 32
# Amiga NDK 3.1: exec/tasks.h and dos/dosextens.h; CLI pointers are BPTRs.
TC_STATE, TASK_SIZE, PR_CLI, CLI_COMMAND_NAME = 15, 92, 172, 16
# Amiga NDK 3.1: exec/ports.h, sizeof(struct MsgPort); private counter follows it.
HEARTBEAT_COUNTER = 34
ROM_END = 0x1000000
RAM_LIMIT = 0x10000000
LIST_RETRIES, LIST_LIMIT, BANK_LIMIT = 20, 200, 16
STATES = ("inv", "added", "run", "ready", "wait", "except", "removed")


@dataclass
class Task:
    name: str
    state: str | int
    type: str | int
    pri: int
    command: str | None = None


@dataclass
class AmigaSample:
    dispatch: int | None = None
    idle: int | None = None
    heartbeat: int | None = None
    tasks: list[Task] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    libraries: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    status: str = "ok"
    error: str | None = None


def be32(value: int) -> bytes:
    return value.to_bytes(4, "big")


class AmigaView:
    def __init__(self, mem: Memory, kickstart_bytes: bytes):
        self.mem = mem
        self.rom = kickstart_bytes
        self.exec = 0
        self.banks: list[tuple[int, int, int]] = []

    def attach(self) -> None:
        self.exec = 0
        self.banks = []
        if not 0x1100 <= len(self.rom) <= ROM_END:
            raise Unreadable("invalid Kickstart size")
        rom_base = ROM_END - len(self.rom)
        hosts = self.mem.find(self.rom[0x1000:0x1100], 10)
        if not hosts:
            raise Unreadable("Kickstart not found in emulator memory")
        rom_bank = (rom_base, ROM_END, hosts[0] - 0x1000 - rom_base)
        offset = self.rom.find(b"exec.library\0")
        while offset >= 0:
            for hit in self.mem.find(be32(rom_base + offset), 2000):
                try:
                    raw = self.mem.read(hit - LN_NAME, EXEC_SIZE)
                    if len(raw) != EXEC_SIZE:
                        continue
                    base = int.from_bytes(raw[CHK_BASE : CHK_BASE + 4], "big") ^ 0xFFFFFFFF
                    if (
                        0x400 < base < RAM_LIMIT
                        and not base & 1
                        and raw[LN_TYPE] == NT_LIBRARY
                        and raw[VBLANK_FREQUENCY] in (50, 60)
                    ):
                        self.exec = base
                        self.banks = [
                            (base & ~0xFFFF, base + 0x1000, hit - LN_NAME - base),
                            rom_bank,
                        ]
                        self._map_memlist()
                        return
                except PermissionError:
                    raise
                except OSError:
                    continue
            offset = self.rom.find(b"exec.library\0", offset + 1)
        self.exec = 0
        self.banks = []
        raise Unreadable("ExecBase/RAM not found: guest not booted or unreadable")

    def _map_memlist(self) -> None:
        bootstrap = self.banks[:]
        head = self.exec + MEM_LIST
        for _ in range(LIST_RETRIES):
            self.banks = bootstrap[:]
            try:
                node, pred = self.u32(head), head
                seen: list[int] = []
                while node != head + LH_TAIL:
                    if not node or node in seen or len(seen) >= BANK_LIMIT:
                        raise Unreadable("invalid MemList chain")
                    seen.append(node)
                    for hit in self.mem.find(be32(pred), 4000):
                        try:
                            raw = self.mem.read(hit - LN_PRED, MH_SIZE)
                        except PermissionError:
                            raise
                        except OSError:
                            continue
                        if len(raw) != MH_SIZE:
                            continue
                        lower = int.from_bytes(raw[MH_LOWER : MH_LOWER + 4], "big")
                        upper = int.from_bytes(raw[MH_UPPER : MH_UPPER + 4], "big")
                        free = int.from_bytes(raw[MH_FREE : MH_FREE + 4], "big")
                        lo, delta = node & ~0xFFFF, hit - LN_PRED - node
                        if (
                            raw[LN_TYPE] == NT_MEMORY
                            and int.from_bytes(raw[LN_PRED : LN_PRED + 4], "big") == pred
                            and node <= lower < node + 0x10000
                            and lower < upper <= RAM_LIMIT
                            and free <= upper - lower
                            and self.mem.contains(lo + delta, upper - lo)
                        ):
                            self.banks.insert(0, (lo, upper, delta))
                            pred, node = node, int.from_bytes(raw[LN_SUCC : LN_SUCC + 4], "big")
                            break
                    else:
                        raise Unreadable("RAM header not found")
                if not seen or self.nodes(head, BANK_LIMIT) != seen:
                    raise Unreadable("MemList changed during discovery")
                self.banks = [*self.banks[: len(seen)], bootstrap[-1]]
                return
            except PermissionError:
                raise
            except OSError:
                time.sleep(0.005)
        raise Unreadable("MemList did not read consistently")

    def get(self, addr: int, size: int) -> bytes:
        error = f"guest range {addr:#x}+{size:#x} is unreadable"
        if size < 0:
            raise Unreadable(error)
        for lo, hi, delta in self.banks:
            if lo <= addr < hi:
                if addr + size > hi:
                    raise Unreadable(error)
                host = addr + delta
                break
        else:
            # UAE's extra area (e.g. 0xF00000) is accessible in a single flat JIT mapping.
            deltas = {delta for _, _, delta in self.banks}
            if len(deltas) != 1 or not 0 <= addr <= addr + size <= RAM_LIMIT:
                raise Unreadable(error)
            host = addr + deltas.pop()
            if not self.mem.contains(host, size):
                raise Unreadable(error)
        raw = self.mem.read(host, size)
        if len(raw) != size:
            raise Unreadable(error)
        return raw

    def u32(self, addr: int) -> int:
        return int.from_bytes(self.get(addr, 4), "big")

    def cstr(self, addr: int, limit: int = 64) -> str:
        raw = bytearray()
        for offset in range(limit):
            char = self.get(addr + offset, 1)[0]
            if not char:
                break
            raw.append(char)
        return raw.decode("latin-1")

    def bstr(self, bptr: int) -> str:
        addr = bptr << 2
        size = self.get(addr, 1)[0]
        return self.get(addr + 1, size).decode("latin-1")

    def nodes(self, head: int, limit: int = LIST_LIMIT) -> list[int]:
        for _ in range(LIST_RETRIES):
            try:
                out: list[int] = []
                node, pred = self.u32(head), head
                while True:
                    if self.u32(node + LN_PRED) != pred:
                        break
                    succ = self.u32(node + LN_SUCC)
                    if node == head + LH_TAIL:
                        if succ == 0:
                            return out
                        break
                    if not succ or node in out or len(out) >= limit:
                        break
                    out.append(node)
                    pred, node = node, succ
            except PermissionError:
                raise
            except OSError:
                pass
            time.sleep(0.005)
        raise Unreadable(f"list at {head:#x} did not read consistently")

    def names(self, head: int) -> list[str]:
        return [self.cstr(self.u32(node + LN_NAME)) for node in self.nodes(head)]

    def task(self, addr: int) -> Task:
        raw = self.get(addr, TASK_SIZE)
        task = Task(
            name=self.cstr(int.from_bytes(raw[LN_NAME : LN_NAME + 4], "big")),
            state=STATES[raw[TC_STATE]] if raw[TC_STATE] < len(STATES) else raw[TC_STATE],
            type={NT_TASK: "task", NT_PROCESS: "process"}.get(raw[LN_TYPE], raw[LN_TYPE]),
            pri=int.from_bytes(raw[LN_PRI : LN_PRI + 1], "big", signed=True),
        )
        if raw[LN_TYPE] == NT_PROCESS:
            cli = self.u32(addr + PR_CLI)
            if cli:
                command = self.u32((cli << 2) + CLI_COMMAND_NAME)
                if command:
                    task.command = self.bstr(command)
        return task

    def sample(self) -> AmigaSample:
        try:
            if not self.exec:
                raise Unreadable("view is not attached")
            if self.u32(self.exec + CHK_BASE) != self.exec ^ 0xFFFFFFFF:
                raise Unreadable("ExecBase changed")
            ports = self.nodes(self.exec + PORT_LIST)
            names = [self.cstr(self.u32(node + LN_NAME)) for node in ports]
            heartbeat = next(
                (
                    self.u32(node + HEARTBEAT_COUNTER)
                    for node, name in zip(ports, names, strict=True)
                    if name == "vmctl.heartbeat"
                ),
                None,
            )
            current = self.u32(self.exec + THIS_TASK)
            tasks = (
                ([current] if current else [])
                + self.nodes(self.exec + TASK_READY)
                + self.nodes(self.exec + TASK_WAIT)
            )
            return AmigaSample(
                dispatch=self.u32(self.exec + DISP_COUNT),
                idle=self.u32(self.exec + IDLE_COUNT),
                heartbeat=heartbeat,
                tasks=[self.task(addr) for addr in dict.fromkeys(tasks)],
                ports=names,
                libraries=self.names(self.exec + LIB_LIST),
                devices=self.names(self.exec + DEVICE_LIST),
            )
        except PermissionError:
            raise
        except OSError as exc:
            return AmigaSample(status="unreadable", error=str(exc))
