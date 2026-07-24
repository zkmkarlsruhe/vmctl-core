"""The plugin contract is the self-describing authoring surface (plugin_spec): an
AI/human writes a plugin straight from it, so it must stay in lock-step with what the
loader actually accepts. These tests assert it can't silently drift."""

from vmctl_core.plugins import PluginRegistry, plugin_spec
from vmctl_core.plugins.contract import _REGISTER_DOCS


def test_every_register_method_is_documented():
    registry_methods = {n for n in dir(PluginRegistry) if n.startswith("register_")}
    assert registry_methods, "no register_* methods found on PluginRegistry"
    missing = registry_methods - set(_REGISTER_DOCS)
    assert not missing, f"register_* methods missing a contract doc: {sorted(missing)}"


def test_plugin_spec_shape():
    spec = plugin_spec()
    assert set(spec) >= {"layout", "manifest_schema", "manifest_example", "registry", "notes"}
    # manifest schema reflects the real PluginManifest fields
    props = spec["manifest_schema"]["properties"]
    assert {"id", "name", "entrypoint", "capabilities"} <= set(props)
    # registry contract covers every register_* method, each with a signature string
    methods = {r["method"] for r in spec["registry"]}
    assert methods == {n for n in dir(PluginRegistry) if n.startswith("register_")}
    for r in spec["registry"]:
        assert r["signature"].startswith(f"registry.{r['method']}(")
