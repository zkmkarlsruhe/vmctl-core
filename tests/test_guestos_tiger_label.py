from vmctl_core.guestos.registry import default_registry


def test_tiger_is_powerpc_not_intel():
    assert default_registry.for_os("mac-os-x-tiger").display_name == "Mac OS X Tiger (PowerPC)"


def test_snow_leopard_stays_intel():
    assert default_registry.for_os("macos-10.6").display_name == "Mac OS X (Intel)"
