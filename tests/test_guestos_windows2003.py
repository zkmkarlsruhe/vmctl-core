"""Windows Server 2003 (NT 5.2) must resolve to a LEGACY cert profile, not the modern fallback.

2003 RTM has no SHA-2 in CryptoAPI, so a MITM leg must present SHA-1/TLSv1 — the same profile
as XP. Before the Windows2003Module, a `windows-2003` label fell through to WindowsModernModule
(SHA-256/TLS1.2), which a pre-patch 2003 guest cannot validate.
"""

from __future__ import annotations

import pytest

from vmctl_core.guestos.modules import Windows2003Module, WindowsModernModule
from vmctl_core.guestos.registry import default_registry


@pytest.mark.parametrize(
    "label",
    ["windows-2003", "win2003", "windows-server-2003", "server-2003", "windows-xp-x64"],
)
def test_2003_labels_resolve_to_2003_module(label):
    m = default_registry.for_os(label)
    assert isinstance(m, Windows2003Module)
    assert not isinstance(m, WindowsModernModule)


def test_2003_gets_legacy_cert_profile():
    m = default_registry.for_os("windows-2003")
    prof = m.cert_profile(None, probe=False)
    assert prof.name == "legacy_nosha2"
    assert prof.leaf_hash == "sha1"
    assert prof.tls_min == "TLSv1"


def test_2003_does_not_hijack_plain_windows():
    # a bare "windows" label still goes to the modern fallback, not 2003
    assert not isinstance(default_registry.for_os("windows"), Windows2003Module)
