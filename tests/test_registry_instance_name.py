"""Regression coverage for the lost VM rename (vmctl#1 / research-vm-controller#1).

``get_instance`` hands out a deep copy so callers can't mutate registry state
outside the lock. Callers that assigned to that copy and then called ``save()``
persisted the *unchanged* stored instance — the rename silently vanished on the
next load. ``set_instance_name`` is the locked, persisting mutation.
"""

import pytest

from vmctl_core.instance import VMInstance
from vmctl_core.project import Registry


def _mk_registry(tmp_path):
    reg = Registry(tmp_path / "state")
    reg.create_project("p")
    reg.add_instance(
        VMInstance(
            id="i1",
            project_id="p",
            base_id="win7",
            domain_name="d-i1",
            overlay_path="/tmp/i1.qcow2",
            xml_path="/tmp/i1.xml",
        )
    )
    return reg


def test_set_instance_name_persists(tmp_path):
    reg = _mk_registry(tmp_path)
    assert reg.set_instance_name("i1", "Exhibit A").name == "Exhibit A"
    assert reg.get_instance("i1").name == "Exhibit A"
    assert Registry(tmp_path / "state").get_instance("i1").name == "Exhibit A"


def test_set_instance_name_trims_and_clears(tmp_path):
    reg = _mk_registry(tmp_path)
    assert reg.set_instance_name("i1", "  Exhibit A  ").name == "Exhibit A"
    for empty in ("", "   ", None):
        assert reg.set_instance_name("i1", empty).name is None
        assert Registry(tmp_path / "state").get_instance("i1").name is None
        reg.set_instance_name("i1", "Exhibit A")


def test_set_instance_name_returns_a_copy(tmp_path):
    reg = _mk_registry(tmp_path)
    returned = reg.set_instance_name("i1", "Exhibit A")
    returned.name = "mutated outside the lock"
    assert reg.get_instance("i1").name == "Exhibit A"


def test_set_instance_name_unknown_instance(tmp_path):
    reg = _mk_registry(tmp_path)
    with pytest.raises(KeyError):
        reg.set_instance_name("nope", "Exhibit A")
