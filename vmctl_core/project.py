"""Projects (realms) + a JSON-on-disk registry.

A project owns N VM instances. The registry is the controller's source of truth
for what exists; it persists to ``<state_dir>/registry.json`` and owns the
``overlays/`` and ``xml/`` directories clones are written into.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from .atomicio import write_text_atomic
from .instance import VMInstance


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
        self.projects: dict[str, Project] = {}
        self.load()

    # --- persistence ------------------------------------------------------
    def load(self) -> None:
        if self._path.exists():
            data = json.loads(self._path.read_text())
            self.projects = {
                pid: Project(**pdata) for pid, pdata in data.get("projects", {}).items()
            }

    def save(self) -> None:
        data = {"projects": {pid: p.model_dump() for pid, p in self.projects.items()}}
        # registry.json is the source of truth — atomic write so an interrupted save
        # can't truncate it and brick load() on the next startup.
        write_text_atomic(self._path, json.dumps(data, indent=2))

    # --- projects ---------------------------------------------------------
    def create_project(self, project_id: str, groups: list[str] | None = None) -> Project:
        if project_id in self.projects:
            raise KeyError(f"project {project_id!r} already exists")
        self.projects[project_id] = Project(id=project_id, groups=groups or [])
        self.save()
        return self.projects[project_id]

    def set_project_groups(self, project_id: str, groups: list[str]) -> Project:
        self.projects[project_id].groups = groups
        self.save()
        return self.projects[project_id]

    def set_project_notes(self, project_id: str, notes: str) -> Project:
        self.projects[project_id].notes = notes
        self.save()
        return self.projects[project_id]

    def set_project_drive_path(self, project_id: str, drive_path: str) -> Project:
        self.projects[project_id].drive_path = drive_path
        self.save()
        return self.projects[project_id]

    def delete_project(self, project_id: str) -> None:
        self.projects.pop(project_id, None)
        self.save()

    def get_project(self, project_id: str) -> Project:
        return self.projects[project_id]

    def list_projects(self) -> list[Project]:
        return list(self.projects.values())

    # --- instances --------------------------------------------------------
    def add_instance(self, inst: VMInstance) -> None:
        self.projects[inst.project_id].instances[inst.id] = inst
        self.save()

    def remove_instance(self, instance_id: str) -> VMInstance:
        for p in self.projects.values():
            if instance_id in p.instances:
                inst = p.instances.pop(instance_id)
                self.save()
                return inst
        raise KeyError(f"instance {instance_id!r} not found")

    def get_instance(self, instance_id: str) -> VMInstance:
        for p in self.projects.values():
            if instance_id in p.instances:
                return p.instances[instance_id]
        raise KeyError(f"instance {instance_id!r} not found")

    def list_instances(self, project_id: str | None = None) -> list[VMInstance]:
        if project_id is not None:
            return list(self.projects[project_id].instances.values())
        return [i for p in self.projects.values() for i in p.instances.values()]
