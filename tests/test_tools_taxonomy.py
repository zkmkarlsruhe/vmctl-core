"""Canonical tool taxonomy (2026-07): category is the function axis, id is derived.

The tools-box grows without bound, so a new tool must be a declarative one-entry add
with a deterministic, collision-resistant id. These tests pin the id scheme
(category.family.slug.version — variant lives in the slug, not the id), the controlled
category vocabulary (in-guest functions only), and the legacy->canonical coercion the
migration relies on.
"""

import pytest

from vmctl_core.tools import (
    CATEGORIES,
    LEGACY_CATEGORY_MAP,
    Tool,
    ToolsLibrary,
    canonical_tool_id,
    coerce_category,
)


def test_categories_are_the_artwork_repair_functions():
    # per-artwork repair tooling ONLY — no golden-build concern (driver) and no
    # exhibition-deployment (kiosk/autologin) category
    assert CATEGORIES == ("runtime", "redist", "unpacker")


def test_canonical_id_shape():
    assert canonical_tool_id("runtime", "flash", "player-sa", "32.0.0.465") == (
        "runtime.flash.player-sa.32-0-0-465"
    )
    # version dots collapse to dashes; segments join on '.'
    assert canonical_tool_id("runtime", "authorware", "web-player", "7.02") == (
        "runtime.authorware.web-player.7-02"
    )


def test_variant_lives_in_the_slug_not_the_id():
    # three Flash variants disambiguate via slug, never a trailing id segment
    ids = {
        canonical_tool_id("runtime", "flash", s, "32.0.0.465")
        for s in ("player-sa", "player-npapi", "player-activex")
    }
    assert ids == {
        "runtime.flash.player-sa.32-0-0-465",
        "runtime.flash.player-npapi.32-0-0-465",
        "runtime.flash.player-activex.32-0-0-465",
    }
    assert not any(i.endswith((".sa", ".npapi", ".activex")) for i in ids)


def test_unknown_category_rejected():
    with pytest.raises(ValueError):
        canonical_tool_id("imaging", "clonezilla", "live", "3.0")  # out-of-guest → not a category


@pytest.mark.parametrize(
    "legacy,canonical",
    [
        ("flash-player", "runtime"),
        ("vrml-3d-viewer", "runtime"),
        ("system-component", "redist"),
        ("runtime", "runtime"),  # already canonical passes through
    ],
)
def test_legacy_category_coercion(legacy, canonical):
    assert coerce_category(legacy) == canonical
    assert LEGACY_CATEGORY_MAP.get(legacy, canonical) == canonical


def test_tool_canonical_id_property_uses_slug_and_family_fallback():
    # family unset → falls back to the runtime line
    t = Tool(
        id="legacy",
        name="Flash Player projector",
        os="winxp",
        runtime="flash",
        version="32.0.0.465",
        variant="sa",
        category="runtime",
        slug="player-sa",
    )
    assert t.canonical_id == "runtime.flash.player-sa.32-0-0-465"


def test_add_file_coerces_category_and_defaults_family(tmp_path):
    lib = ToolsLibrary(tmp_path)
    binary = tmp_path / "player.exe"
    binary.write_bytes(b"MZ stub")
    t = lib.add_file(
        binary,
        id="runtime.flash.player-sa.32-0-0-465",
        name="Flash Player projector",
        os="winxp",
        runtime="flash",
        version="32.0.0.465",
        variant="sa",
        extra={"category": "flash-player", "slug": "player-sa"},  # legacy value coerces
    )
    assert t.category == "runtime"
    assert t.family == "flash"  # defaulted from runtime
    assert t.canonical_id == "runtime.flash.player-sa.32-0-0-465"
