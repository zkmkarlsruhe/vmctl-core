"""Stateful counter checks. State belongs to the caller, never to a global cache."""

from __future__ import annotations

import time
from dataclasses import asdict
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .amiga import AmigaSample, AmigaView
from .mac68k import MacView
from .memory import ProcMemory, Unreadable

if TYPE_CHECKING:
    from ..backends.process import ProbeSpec


def probe(spec: ProbeSpec, pid: int, state: dict[str, Any]) -> tuple[bool | None, dict]:
    """Track counter freshness across polls; a new baseline initially warms up.

    Kickstart must be resolved by the caller against its instance directory. Expected
    names match case-insensitively and exactly; Amiga CLI paths also match their basename.
    max_age_s bounds time since observed progress, including polls with equal values.
    """
    try:
        with ProcMemory(pid) as mem:
            identity = (
                mem.identity,
                spec.kind,
                spec.kickstart,
                spec.ram_bytes,
                tuple(spec.expect),
                spec.max_age_s,
            )
            if state.get("identity") != identity:
                state.clear()
            view: AmigaView | MacView | None = state.get("view")
            if view is None:
                if spec.kind == "amiga":
                    view = AmigaView(mem, Path(spec.kickstart).read_bytes())
                else:
                    view = MacView(mem, spec.ram_bytes)
                view.attach()
                state.update(identity=identity, view=view)
            else:
                view.mem = mem
            sample = view.sample()
            detail = {"pid": pid, "kind": spec.kind, **asdict(sample)}
            if sample.status != "ok":
                raise Unreadable(sample.error)
            names: set[str] = set()
            if isinstance(sample, AmigaSample):
                source = "heartbeat" if sample.heartbeat is not None else "dispatch"
                counter = sample.heartbeat if sample.heartbeat is not None else sample.dispatch
                for task in sample.tasks:
                    names.add(task.name.casefold())
                    if task.command:
                        names.add(task.command.casefold())
                        names.add(task.command.rsplit("/", 1)[-1].rsplit(":", 1)[-1].casefold())
            else:
                source, counter = "ticks", sample.ticks
                names.add((sample.cur_app or "").casefold())
            if counter is None:
                raise Unreadable("missing liveness counter")
            missing = [name for name in spec.expect if name.casefold() not in names]
            now = time.monotonic()
            previous = state.get("previous")
            if previous is None or previous[0] != source:
                state.update(attached_at=now, last_change=None, progressed=False)
            elif counter != previous[1]:
                # Modular subtraction accepts wraparound but rejects reset/backward jumps.
                advanced = 0 < ((counter - previous[1]) & 0xFFFFFFFF) < 0x80000000
                state.update(last_change=now, progressed=advanced)
            last_change = state["last_change"]
            alive: bool | None
            if last_change is None and now - state["attached_at"] < spec.max_age_s:
                alive, reason = None, "warming up"
            else:
                fresh = last_change is not None and 0 <= now - last_change <= spec.max_age_s
                alive = fresh and state["progressed"] and not missing
                reason = (
                    "ok"
                    if alive
                    else "expected program missing"
                    if missing
                    else "counter stuck"
                    if not fresh
                    else "counter reset"
                )
            detail.update(alive=alive, reason=reason, counter=source, missing=missing)
            state.update(previous=(source, counter), detail=detail)
            return alive, detail
    except PermissionError:
        state.clear()
        raise
    except OSError as exc:
        state.clear()
        detail = {
            "pid": pid,
            "kind": spec.kind,
            "alive": False,
            "status": "unreadable",
            "reason": "unreadable",
            "error": str(exc),
        }
        state["detail"] = detail
        return False, detail
