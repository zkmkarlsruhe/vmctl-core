"""research/65 §B — the dependency / Technical-Environment resolver.

The flat catalog + Tool.relations is a graph; these tests pin that a format need
resolves to the runnable stack the AI analyst asks for: the binary, its recursive
depends_on chain, conservation quirks, and alternatives — ranked by OS fit + presence.
"""

from vmctl_core.tools import REL_TYPES, Tool, ToolsLibrary


def _lib(tmp_path):
    lib = ToolsLibrary(tmp_path)
    lib.tools = {
        "runtime.director.shockwave-player.12-3-5-205": Tool(
            id="runtime.director.shockwave-player.12-3-5-205",
            name="Shockwave Player",
            os="winxp",
            runtime="director",
            family="director",
            slug="shockwave-player",
            version="12.3.5.205",
            category="runtime",
            handles_mime=["application/x-director"],
            handles_ext=[".dcr", ".dxr", ".dir"],
            os_compat=["windows-xp"],
            relations=[
                {"rel": "depends_on", "target": "director-xtras", "note": "Xtras beside projector"},
                {"rel": "reads_format", "target": "x-fmt/396", "mime": "application/x-director"},
            ],
        ),
        "runtime.quicktime.player-win.7-7-9": Tool(
            id="runtime.quicktime.player-win.7-7-9",
            name="QuickTime 7",
            os="winxp",
            runtime="quicktime",
            family="quicktime",
            slug="player-win",
            version="7.7.9",
            category="runtime",
            handles_mime=["video/quicktime"],
            os_compat=["windows-xp", "windows-7"],
            known_cves=["CVE-2016-1767"],
            install_mode="interactive",
        ),
        "unpacker.stuffit.expander.5-5": Tool(
            id="unpacker.stuffit.expander.5-5",
            name="StuffIt Expander",
            os="macos9",
            runtime="stuffit",
            family="stuffit",
            slug="expander",
            version="5.5",
            category="unpacker",
            handles_ext=[".sit"],
            os_compat=["mac-os-9"],
            relations=[{"rel": "alternative_to", "target_id": "unpacker.unar.cli.1-10-1"}],
        ),
    }
    return lib


def test_rel_types_exported():
    assert "depends_on" in REL_TYPES and "reads_format" in REL_TYPES


def test_reads_by_mime_and_by_puid(tmp_path):
    lib = _lib(tmp_path)
    assert [t.id for t in lib.reads(mime="application/x-director")] == [
        "runtime.director.shockwave-player.12-3-5-205"
    ]
    # reads_format relation resolves a PRONOM PUID even without handles_mime
    assert [t.id for t in lib.reads(puid="x-fmt/396")] == [
        "runtime.director.shockwave-player.12-3-5-205"
    ]


def test_technical_environment_chain_and_quirks(tmp_path):
    lib = _lib(tmp_path)
    te = lib.technical_environment("runtime.director.shockwave-player.12-3-5-205")
    assert te["depends_on"][0]["id"] == "director-xtras"
    assert te["depends_on"][0]["in_catalog"] is False  # a known gap, still surfaced
    te2 = lib.technical_environment("runtime.quicktime.player-win.7-7-9")
    assert any("OFFLINE" in q for q in te2["quirks"])  # CVE -> offline quirk


def test_alternatives_surfaced(tmp_path):
    lib = _lib(tmp_path)
    te = lib.technical_environment("unpacker.stuffit.expander.5-5")
    assert te["alternatives"] == ["unpacker.unar.cli.1-10-1"]


def test_resolve_ranks_os_match_first(tmp_path):
    lib = _lib(tmp_path)
    # add a second reader of video/quicktime with no XP support
    lib.tools["runtime.qt.player-mac.7"] = Tool(
        id="runtime.qt.player-mac.7",
        name="QT mac",
        os="macosx",
        runtime="quicktime",
        family="quicktime",
        slug="player-mac",
        version="7",
        category="runtime",
        handles_mime=["video/quicktime"],
        os_compat=["mac-os-x"],
    )
    out = lib.resolve(mime="video/quicktime", os="windows-xp")
    assert out[0]["tool"] == "runtime.quicktime.player-win.7-7-9"  # os match wins
    assert out[0]["os_match"] is True and out[-1]["os_match"] is False
