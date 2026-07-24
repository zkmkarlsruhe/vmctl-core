"""Plugin skeleton generator (`rvmc plugin new <name>`).

Drops a ready-to-edit plugin directory conforming to the shared spec into the
workspace, so the researcher opens code-server onto a working starting point.
"""

from __future__ import annotations

import re
from pathlib import Path

_MANIFEST = """\
id: {id}
name: {name}
version: 0.1.0
author: ""
license: MIT
entrypoint: plugin.py
description: "TODO: what this plugin does for the artwork"
target:
  os: null
  base_id: null
capabilities: []
"""

_PLUGIN_PY = '''\
"""{name} — research/exhibition plugin.

Implements the shared plugin spec: expose `setup(registry)` and register against
the registry. This same file runs unchanged in the exhibition controller.
"""

from pathlib import Path

WEB = Path(__file__).parent / "web"


def setup(registry):
    # Serve this plugin's web content (return HTML str or None to pass through).
    def web(path: str):
        if path in ("", "/", "index.html"):
            index = WEB / "index.html"
            if index.is_file():
                return index.read_text()
        return None

    registry.register_web_handler(web)

    # Example state + poll providers (read by the controller / AI / Arduino).
    registry.register_state_provider("{id}", lambda: {{"status": "ready"}})
    registry.register_poll_provider("{id}", lambda: "ready")

    # Example signal handler (the guest / UI can fire /api/v1/signal/{id}-hello).
    registry.register_signal_handler("{id}-hello", lambda value: None)
'''

_INDEX_HTML = """\
<!doctype html>
<meta charset="utf-8">
<title>{name}</title>
<h1>{name}</h1>
<p>Plugin skeleton — edit <code>plugin.py</code> and this page.</p>
"""


def slugify(name: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", name.strip().lower()).strip("-")
    return s or "plugin"


def new_plugin(name: str, plugins_dir: str | Path) -> Path:
    """Create plugins_dir/<slug>/ with manifest.yaml, plugin.py and web/index.html.
    Returns the plugin directory. Refuses to overwrite an existing one."""
    pid = slugify(name)
    root = Path(plugins_dir) / pid
    if root.exists():
        raise FileExistsError(f"plugin directory already exists: {root}")
    (root / "web").mkdir(parents=True)
    (root / "manifest.yaml").write_text(_MANIFEST.format(id=pid, name=name))
    (root / "plugin.py").write_text(_PLUGIN_PY.format(id=pid, name=name))
    (root / "web" / "index.html").write_text(_INDEX_HTML.format(name=name))
    return root
