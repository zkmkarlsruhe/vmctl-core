"""Projects (realms) + a JSON-on-disk registry.

A project owns N VM instances. The registry is the controller's source of truth
for what exists; it persists to ``<state_dir>/registry.json`` and owns the
``overlays/`` and ``xml/`` directories clones are written into.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path

from pydantic import BaseModel, Field

from vmctl_core.atomicio import write_text_atomic
from vmctl_core.instance import VMInstance


class Project(BaseModel):
    id: str
    groups: list[str] = Field(default_factory=list)  # Authentik groups granted access
    notes: str = ""  # per-project markdown notes
    drive_path: str = ""  # the artwork drive (research/68); "" = none yet
    instances: dict[str, VMInstance] = Field(default_factory=dict)


class Registry:
    def __init__(self, state_dir: str | Path) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.overlays_dir = self.state_dir / "overlays"
        self.xml_dir = self.state_dir / "xml"
        self._path = self.state_dir / "registry.json"
        # The registry singleton is mutated concurrently from FastAPI's sync-handler threadpool.
        # A REENTRANT lock guards every mutate+save AND every read that iterates the shared dict:
        # without it two overlapping mutate→save pairs interleave and the later os.replace() writes
        # a snapshot missing the other's change (silent lost update), and a read iterating while a
        # write pops/adds can raise "dict changed size during iteration". Reentrant so a mutator can
        # call save() (which also takes the lock) without deadlocking.
        # LIMIT: the lock is PROCESS-LOCAL. A second process/worker on the same state dir
        # bypasses it entirely — saves are atomic (no torn files) but last-writer-wins.
        # The deployment contract is therefore ONE controller process per state dir.
        self._lock = threading.RLock()
        self.projects: dict[str, Project] = {}
        self.load()

    # --- persistence ------------------------------------------------------
    def load(self) -> None:
        with self._lock:
            if self._path.exists():
                data = json.loads(self._path.read_text())
                self.projects = {
                    pid: Project(**pdata) for pid, pdata in data.get("projects", {}).items()
                }

    def save(self) -> None:
        with self._lock:
            data = {"projects": {pid: p.model_dump() for pid, p in self.projects.items()}}
            # registry.json is the source of truth — atomic write so an interrupted save
            # can't truncate it and brick load() on the next startup.
            write_text_atomic(self._path, json.dumps(data, indent=2))

    # --- projects ---------------------------------------------------------
    def create_project(self, project_id: str, groups: list[str] | None = None) -> Project:
        with self._lock:
            if project_id in self.projects:
                raise KeyError(f"project {project_id!r} already exists")
            self.projects[project_id] = Project(id=project_id, groups=groups or [])
            self.save()
            return self.projects[project_id]

    def set_project_groups(self, project_id: str, groups: list[str]) -> Project:
        with self._lock:
            self.projects[project_id].groups = groups
            self.save()
            return self.projects[project_id]

    def set_project_notes(self, project_id: str, notes: str) -> Project:
        with self._lock:
            self.projects[project_id].notes = notes
            self.save()
            return self.projects[project_id]

    def set_project_drive_path(self, project_id: str, drive_path: str) -> Project:
        with self._lock:
            self.projects[project_id].drive_path = drive_path
            self.save()
            return self.projects[project_id]

    def delete_project(self, project_id: str) -> None:
        with self._lock:
            self.projects.pop(project_id, None)
            self.save()

    def get_project(self, project_id: str) -> Project:
        # Deep-copy so a caller mutating the returned Project (outside the lock) can't
        # edit registry state in place and re-introduce the very race the RLock prevents.
        with self._lock:
            return self.projects[project_id].model_copy(deep=True)

    def list_projects(self) -> list[Project]:
        with self._lock:
            return [p.model_copy(deep=True) for p in self.projects.values()]

    # --- instances --------------------------------------------------------
    def add_instance(self, inst: VMInstance) -> None:
        with self._lock:
            self.projects[inst.project_id].instances[inst.id] = inst
            self.save()

    def remove_instance(self, instance_id: str) -> VMInstance:
        with self._lock:
            for p in self.projects.values():
                if instance_id in p.instances:
                    inst = p.instances.pop(instance_id)
                    self.save()
                    return inst
            raise KeyError(f"instance {instance_id!r} not found")

    def set_instance_name(self, instance_id: str, name: str | None) -> VMInstance:
        """Set/clear an instance's friendly display name and persist it.

        get_instance() hands out a deep copy, so a caller that assigns to that copy
        and calls save() writes the *unchanged* stored instance back to disk. Name
        changes therefore have to go through the registry, under the lock.
        """
        cleaned = (name or "").strip() or None
        with self._lock:
            for p in self.projects.values():
                inst = p.instances.get(instance_id)
                if inst is not None:
                    inst.name = cleaned
                    self.save()
                    return inst.model_copy(deep=True)
            raise KeyError(f"instance {instance_id!r} not found")

    def get_instance(self, instance_id: str) -> VMInstance:
        # Deep-copy (see get_project): the caller must not mutate registry state in place.
        with self._lock:
            for p in self.projects.values():
                if instance_id in p.instances:
                    return p.instances[instance_id].model_copy(deep=True)
            raise KeyError(f"instance {instance_id!r} not found")

    def list_instances(self, project_id: str | None = None) -> list[VMInstance]:
        with self._lock:
            if project_id is not None:
                return [
                    i.model_copy(deep=True) for i in self.projects[project_id].instances.values()
                ]
            return [
                i.model_copy(deep=True)
                for p in self.projects.values()
                for i in p.instances.values()
            ]
