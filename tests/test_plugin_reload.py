"""Hot reload: `load_plugins` must pick up edited plugin code without a controller restart.

Regression guard for the sys.modules-cache footgun — before `_purge_plugin_modules`, a re-load
re-ran setup() but served the plugin's cached sibling package, so a code change needed a full restart.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

from vmctl_core.plugins import PluginRegistry, load_plugins
from vmctl_core.plugins.runtime import _purge_plugin_modules

_PLUGIN_PY = """\
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from hotpkg_xyz import VALUE  # a sibling package that gets edited between loads


def setup(registry):
    registry.register_state_provider("v", lambda: {"v": VALUE})
"""


def _write_plugin(root: Path, value: str) -> None:
    plug = root / "hotplug"
    (plug / "hotpkg_xyz").mkdir(parents=True, exist_ok=True)
    (plug / "manifest.yaml").write_text("id: hotplug\nname: Hot\nentrypoint: plugin.py\n")
    (plug / "plugin.py").write_text(_PLUGIN_PY)
    (plug / "hotpkg_xyz" / "__init__.py").write_text(f'VALUE = "{value}"\n')


def test_reload_picks_up_edited_submodule(tmp_path):
    try:
        _write_plugin(tmp_path, "first")
        reg1 = PluginRegistry()
        load_plugins(tmp_path, reg1)
        assert reg1.get_state()["v"]["v"] == "first"

        # edit the sibling package and reload into a fresh registry
        _write_plugin(tmp_path, "second")
        reg2 = PluginRegistry()
        load_plugins(tmp_path, reg2)
        assert (
            reg2.get_state()["v"]["v"] == "second"
        )  # would be "first" without the sys.modules purge
    finally:
        sys.modules.pop("hotpkg_xyz", None)
        for p in [str(tmp_path / "hotplug")]:
            if p in sys.path:
                sys.path.remove(p)


def test_purge_uses_path_containment_not_string_prefix(tmp_path):
    """bug 8: a raw ``startswith(str(plugin_dir))`` also matches a SIBLING whose name merely starts
    with this one — reloading ``foo`` would wrongly purge ``foobar``/``foo-v2`` modules. Path
    containment (is_relative_to) compares on directory boundaries, so the sibling survives."""
    foo = tmp_path / "foo"
    foobar = tmp_path / "foobar"  # name is a string-prefix of "foo" + "bar"
    foo.mkdir()
    foobar.mkdir()
    (foo / "m.py").write_text("x = 1\n")
    (foobar / "m.py").write_text("x = 2\n")

    mod_foo = types.ModuleType("purge_probe_foo")
    mod_foo.__file__ = str(foo / "m.py")
    mod_foobar = types.ModuleType("purge_probe_foobar")
    mod_foobar.__file__ = str(foobar / "m.py")
    sys.modules["purge_probe_foo"] = mod_foo
    sys.modules["purge_probe_foobar"] = mod_foobar
    try:
        _purge_plugin_modules(foo)
        assert "purge_probe_foo" not in sys.modules  # lives under foo/ -> purged
        assert "purge_probe_foobar" in sys.modules  # sibling -> untouched (was the bug)
    finally:
        sys.modules.pop("purge_probe_foo", None)
        sys.modules.pop("purge_probe_foobar", None)
