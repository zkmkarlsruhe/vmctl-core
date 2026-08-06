"""Router core: claim matching, the rung ladder (plugin first refusal + decline/terminal),
and cross-plugin claim-conflict detection.
"""

from __future__ import annotations

import pytest

from vmctl_core.plugins.spec import PluginClaim, PluginManifest
from vmctl_core.router import (
    DECLINE,
    Flow,
    Handled,
    Router,
    Terminal,
    claim_matches,
    detect_claim_conflicts,
)


def _http(host="api.example", port=80, method="GET", path="/x"):
    return Flow(proto="http", dst_host=host, dst_port=port, method=method, path=path)


# --- claim matching -----------------------------------------------------------
def test_bare_host_claim_matches_http_and_https():
    c = PluginClaim(host="api.example")
    assert claim_matches(c, _http(port=80))
    assert claim_matches(c, Flow(proto="https", dst_host="api.example", dst_port=443, method="GET"))
    assert not claim_matches(c, _http(host="other.example"))


def test_method_narrowing():
    c = PluginClaim(host="api.example", methods=["POST"])
    assert claim_matches(c, _http(method="POST"))
    assert not claim_matches(c, _http(method="GET"))


def test_path_narrowing():
    c = PluginClaim(host="api.example", paths=["/api/*"])
    assert claim_matches(c, _http(path="/api/v1/x"))
    assert not claim_matches(c, _http(path="/other"))


def test_port_and_proto_narrowing():
    c = PluginClaim(host="h", ports=[1935], protocols=["tcp"])
    assert claim_matches(c, Flow(proto="tcp", dst_host="h", dst_port=1935))
    assert not claim_matches(c, Flow(proto="tcp", dst_host="h", dst_port=80))


# --- effective_claims (backend_host shorthand) --------------------------------
def test_backend_host_expands_to_default_claim():
    m = PluginManifest(id="p", name="p", backend_host="192.168.29.29")
    cs = m.effective_claims()
    assert len(cs) == 1 and cs[0].host == "192.168.29.29"
    assert cs[0].protocols == ["http", "https"]


def test_explicit_claims_win_over_backend_host():
    m = PluginManifest(
        id="p",
        name="p",
        backend_host="ignored",
        claims=[PluginClaim(host="real", methods=["POST"])],
    )
    cs = m.effective_claims()
    assert [c.host for c in cs] == ["real"]


def test_no_claim_for_ui_plugin():
    assert PluginManifest(id="p", name="p").effective_claims() == []


# --- the ladder ---------------------------------------------------------------
class _Rung:
    def __init__(self, name, outcome, handles=True):
        self.name = name
        self._outcome = outcome
        self._handles = handles
        self.seen = 0

    def can_handle(self, flow):
        return self._handles

    def handle(self, flow):
        self.seen += 1
        return self._outcome


def test_first_non_decline_wins():
    plugin = _Rung("plugin", Handled("from-plugin"))
    archive = _Rung("archive", Handled("from-archive"))
    r = Router(rungs=[plugin, archive])
    out = r.route(_http())
    assert isinstance(out, Handled) and out.response == "from-plugin"
    assert archive.seen == 0  # plugin answered; archive never consulted


def test_decline_falls_through():
    plugin = _Rung("plugin", DECLINE)
    archive = _Rung("archive", Handled("from-archive"))
    r = Router(rungs=[plugin, archive])
    out = r.route(_http())
    assert isinstance(out, Handled) and out.response == "from-archive"
    assert plugin.seen == 1


def test_terminal_stops_no_fallthrough():
    plugin = _Rung("plugin", Terminal(status=404))
    archive = _Rung("archive", Handled("from-archive"))
    r = Router(rungs=[plugin, archive])
    out = r.route(_http())
    assert isinstance(out, Terminal) and out.status == 404
    assert archive.seen == 0  # owned-but-absent must NOT get archive content


def test_can_handle_false_skips_rung():
    plugin = _Rung("plugin", Handled("x"), handles=False)
    archive = _Rung("archive", Handled("from-archive"))
    r = Router(rungs=[plugin, archive])
    assert r.route(_http()).response == "from-archive"
    assert plugin.seen == 0


def test_ladder_miss_returns_none():
    r = Router(rungs=[_Rung("a", DECLINE), _Rung("b", DECLINE)])
    assert r.route(_http()) is None


def test_raising_rung_propagates():
    class _Boom:
        name = "boom"

        def can_handle(self, flow):
            return True

        def handle(self, flow):
            raise RuntimeError("plugin crashed")

    r = Router(rungs=[_Boom(), _Rung("archive", Handled("x"))])
    with pytest.raises(RuntimeError):
        r.route(_http())  # not swallowed into a silent fallthrough


# --- conflict detection -------------------------------------------------------
def test_conflict_on_same_host():
    conflicts = detect_claim_conflicts({"a": [PluginClaim(host="h")], "b": [PluginClaim(host="h")]})
    assert conflicts == [("a", "b", "h")]


def test_no_conflict_distinct_hosts():
    assert (
        detect_claim_conflicts({"a": [PluginClaim(host="h1")], "b": [PluginClaim(host="h2")]}) == []
    )


def test_no_conflict_when_ports_disjoint():
    conflicts = detect_claim_conflicts(
        {
            "a": [PluginClaim(host="h", ports=[80], protocols=["http"])],
            "b": [PluginClaim(host="h", ports=[1935], protocols=["tcp"])],
        }
    )
    assert conflicts == []
