"""VMInstance — a single cloned VM living inside a project."""

from __future__ import annotations

from pydantic import BaseModel


class VMInstance(BaseModel):
    id: str  # short instance id (unique within the deployment)
    name: str | None = None  # friendly display name (UI label); id stays the stable internal id
    project_id: str
    base_id: str  # which catalog base this was cloned from
    domain_name: str  # the libvirt domain name
    overlay_path: str  # the CoW qcow2 overlay
    xml_path: str  # the rendered domain definition
    created_at: str | None = None
