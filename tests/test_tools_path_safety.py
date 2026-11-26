"""Path-confinement + locking regression guards for the tools box (2026-07 bug-pass).

The tools box builds on-disk locations by interpolating a tool's ``os/runtime/version`` into
``<root>/<os>/<runtime>/<version>`` and by joining a catalogued ``path`` onto ``root``. Both are
trusted-ish inputs, but a poisoned catalog.json entry or an ``os="../../etc"`` argument must not
let a load/use/unlink/import reach OUTSIDE the tools root. ``ToolsLibrary`` is also a shared
singleton mutated from the FastAPI threadpool, so its mutate+save pairs must be serialised.
"""

import json
import threading

import pytest

from vmctl_core.paths import safe_segment
from vmctl_core.tools import Tool, ToolsLibrary, _confined_path


def _mk_lib(tmp_path):
    lib = ToolsLibrary(tmp_path / "box")
    return lib


# --- bug 1: catalogued path can't escape the tools root ----------------------------------------


def test_confined_path_rejects_traversal(tmp_path):
    root = tmp_path / "box"
    root.mkdir()
    with pytest.raises(ValueError):
        _confined_path(root, "../../../etc/passwd")
    # a legitimate in-box relative path resolves fine
    assert _confined_path(root, "winxp/flash/1/f.exe") == (root / "winxp/flash/1/f.exe").resolve()


def test_load_rejects_poisoned_escaping_path(tmp_path):
    lib = _mk_lib(tmp_path)
    # Hand-write a poisoned catalog whose path climbs out of the box.
    lib._catalog.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "id": "evil",
                        "name": "evil",
                        "os": "winxp",
                        "runtime": "flash",
                        "version": "1",
                        "path": "../../../../home/user/.ssh/id_ed25519",
                    }
                ]
            }
        )
    )
    with pytest.raises(ValueError):
        lib.load()


def test_delete_remove_file_wont_unlink_outside_root(tmp_path):
    lib = _mk_lib(tmp_path)
    # A file that lives OUTSIDE the box — a poisoned entry must never unlink it.
    victim = tmp_path / "victim.key"
    victim.write_text("secret")
    # Inject the poisoned entry directly (bypassing register's guard) to prove delete re-checks.
    lib.tools["poison"] = Tool(
        id="poison",
        name="poison",
        os="winxp",
        runtime="flash",
        version="1",
        path="../victim.key",
    )
    with pytest.raises(ValueError):
        lib.delete("poison", remove_file=True)
    assert victim.exists()  # untouched — the confinement raised before unlink
    assert "poison" in lib.tools  # catalog left intact on the raise


def test_abs_path_confines(tmp_path):
    lib = _mk_lib(tmp_path)
    lib.tools["poison"] = Tool(
        id="poison", name="p", os="winxp", runtime="flash", version="1", path="../../etc/x"
    )
    with pytest.raises(ValueError):
        lib.abs_path("poison")


# --- bug 2: add_file location segments can't be traversal payloads -----------------------------


def test_safe_segment_rejects_separators_and_dotdot():
    for bad in ("../../etc", "a/b", "..", ".", "", "foo/bar"):
        with pytest.raises(ValueError):
            safe_segment(bad, field="os")
    assert safe_segment("winxp", field="os") == "winxp"


@pytest.mark.parametrize("field", ["os", "runtime", "version"])
def test_add_file_rejects_escaping_segment(tmp_path, field):
    lib = _mk_lib(tmp_path)
    src = tmp_path / "player.exe"
    src.write_bytes(b"MZ")
    kwargs = dict(
        id="t1",
        name="t",
        os="winxp",
        runtime="flash",
        version="1",
    )
    kwargs[field] = "../../etc"
    with pytest.raises(ValueError):
        lib.add_file(src, **kwargs)
    # nothing escaped the box
    assert not (tmp_path / "etc").exists()


# --- bug 3: ToolsLibrary serialises concurrent mutate+save (no lost update) ---------------------


def test_concurrent_register_no_lost_update(tmp_path):
    lib = _mk_lib(tmp_path)
    n_threads, per_thread = 8, 25
    barrier = threading.Barrier(n_threads)

    def worker(t: int):
        barrier.wait()
        for j in range(per_thread):
            lib.register(Tool(id=f"t{t}-{j}", name="x", os="winxp", runtime="flash", version="1"))

    threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()

    expected = n_threads * per_thread
    assert len(lib.tools) == expected
    # the on-disk catalog agrees (a lost update would show as a short reload)
    reloaded = ToolsLibrary(tmp_path / "box")
    assert len(reloaded.tools) == expected


def test_read_during_write_does_not_raise(tmp_path):
    lib = _mk_lib(tmp_path)
    stop = threading.Event()
    errors: list[Exception] = []

    def writer():
        for i in range(300):
            lib.register(Tool(id=f"w{i}", name="x", os="winxp", runtime="flash", version="1"))
        stop.set()

    def reader():
        try:
            while not stop.is_set():
                lib.list()
        except Exception as e:  # pragma: no cover - only on a regression
            errors.append(e)

    w = threading.Thread(target=writer)
    r = threading.Thread(target=reader)
    w.start()
    r.start()
    w.join()
    r.join()
    assert not errors, errors
    assert len(lib.tools) == 300
