from vmctl_core.catalog import BaseImage, Catalog


def test_a_base_runs_its_os_and_its_aliases() -> None:
    b = BaseImage(id="win98", path="x.qcow2", os="windows-98", os_aliases=["windows-9x"])
    assert b.runs("windows-98") and b.runs("Windows 9x") and not b.runs("windows-xp")
    assert not b.runs("")


def test_aliases_default_empty_and_load_from_yaml_shape() -> None:
    c = Catalog(**{"bases": [{"id": "a", "path": "a.qcow2", "os": "mac-os-9"}]})
    assert c.bases[0].os_aliases == [] and c.bases[0].runs("mac-os-9")
