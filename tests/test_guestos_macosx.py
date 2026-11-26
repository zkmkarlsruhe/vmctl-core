"""Mac OS X (Snow Leopard 10.6) GuestOS module.

Locks the three things that matter: (1) the registry resolves macOS-X labels to
MacOSXModule and does NOT let the classic MacOS9 "mac-os" prefix win; (2) the
declared capability set (and how gate_by_agent degrades an agentless base); (3) the
behaviour bodies drive the snowleopard agent's run_shell contract correctly — proven
with a fake GuestContext, exactly as the module contract intends.
"""

from __future__ import annotations

from vmctl_core.agentwire import Reply
from vmctl_core.catalog import BaseImage
from vmctl_core.guestos.capabilities import Capabilities, Capability, gate_by_agent
from vmctl_core.guestos.modules import MacOS9Module, MacOSXModule
from vmctl_core.guestos.registry import default_registry


class FakeContext:
    """Records agent calls and returns canned run_shell results. Matches the
    GuestContext surface the module uses (guest_call + guest_write_file)."""

    def __init__(self, stdout: str = "", exit_code: int = 0):
        self.instance_id = "sl1"
        self.base = BaseImage(id="macos-10.6", os="macos-10.6", path="x", agent=True)
        self.calls: list[tuple[str, dict]] = []
        self.written: list[tuple[str, bytes]] = []
        self._stdout = stdout
        self._exit = exit_code

    def guest_call(self, tool: str, *, timeout: float = 30.0, **args) -> Reply:
        self.calls.append((tool, args))
        return Reply(
            {"exit": str(self._exit), "stdout": self._stdout, "stderr": "", "truncated": "0"},
            "-",
            None,
        )

    def guest_write_file(self, path: str, data: bytes) -> None:
        self.written.append((path, data))


# --- resolution ---------------------------------------------------------------
def test_registry_resolves_macos_x_not_os9():
    # the whole point of longest-prefix: macos-10.6 must NOT fall to MacOS9's "mac-os"
    assert isinstance(default_registry.for_os("macos-10.6"), MacOSXModule)
    assert isinstance(default_registry.for_os("mac-os-x"), MacOSXModule)
    assert isinstance(default_registry.for_os("snow-leopard"), MacOSXModule)
    assert isinstance(default_registry.for_os("darwin"), MacOSXModule)
    # ...and the classic labels still resolve to OS 9, unaffected
    assert isinstance(default_registry.for_os("mac-os-9"), MacOS9Module)
    assert isinstance(default_registry.for_os("macos9"), MacOS9Module)


# --- capabilities -------------------------------------------------------------
def test_caps_declared_and_withheld():
    caps = MacOSXModule().caps()
    for c in (
        Capability.AGENT,
        Capability.READ_LOGS,
        Capability.INSTALL_CA,
        Capability.CERT_PROFILE,
        Capability.CONFIGURE_PROXY,
        Capability.HANDLE_DIALOGS,
        Capability.AUDIO_SETUP,
        Capability.DATALINK_MOUNT,
        Capability.MAKE_GOLDEN,
    ):
        assert caps.supports(c), f"expected {c}"
    for c in (
        Capability.READ_EVENT_LOG,  # Windows-only
        Capability.INSTALL_CA_BROWSER,  # Safari = system keychain
        Capability.CONFIGURE_BROWSER,  # no browser-only knob on 10.6
        Capability.PROVISION_DRIVERS,  # all in-box
        Capability.SET_RESOLUTION,  # fixed under unaccelerated framebuffer
    ):
        assert not caps.supports(c), f"unexpected {c}"


def test_gate_by_agent_degrades_to_stub():
    caps = MacOSXModule().caps()
    gated = gate_by_agent(caps, agent=False)
    # The agent-dependent caps (agent/read_logs/install_ca/configure_proxy/handle_dialogs)
    # drop on an agentless base; what survives is what the framework classes as NOT
    # agent-gated: the universal CD + golden recipe, plus the pure static cert opinion and
    # audio_setup (same non-gated policy as the Linux module — see AGENT_DEPENDENT).
    assert gated == Capabilities.of(
        Capability.DATALINK_MOUNT,
        Capability.MAKE_GOLDEN,
        Capability.CERT_PROFILE,
        Capability.AUDIO_SETUP,
    )
    # the scriptable, agent-driven controls are gone
    for c in (
        Capability.AGENT,
        Capability.READ_LOGS,
        Capability.INSTALL_CA,
        Capability.CONFIGURE_PROXY,
        Capability.HANDLE_DIALOGS,
    ):
        assert not gated.supports(c)


# --- pure bodies --------------------------------------------------------------
def test_cert_profile_is_legacy_sha2():
    cp = MacOSXModule().cert_profile(FakeContext())
    assert (cp.name, cp.leaf_hash, cp.cipher_profile, cp.tls_min) == (
        "legacy_sha2",
        "sha256",
        "legacy",
        "TLSv1",
    )


def test_agent_transport_is_tcp():
    assert MacOSXModule().agent_transport(FakeContext()) == "tcp"


# --- agent-driven bodies (fake context) --------------------------------------
def test_read_logs_parses_run_shell_stdout():
    ctx = FakeContext(stdout="line one\n\nline two\n")
    recs = MacOSXModule().read_logs(ctx, kind="system", count=10)
    assert [r.message for r in recs] == ["line one", "line two"]
    tool, args = ctx.calls[0]
    assert tool == "run_shell"
    assert "/var/log/system.log" in args["cmd"] and "tail -n 10" in args["cmd"]


def test_configure_proxy_issues_networksetup():
    ctx = FakeContext()
    out = MacOSXModule().configure_proxy(ctx, addr="10.0.0.1:8080", bypass="localhost,*.local")
    assert out["ok"] and out["addr"] == "10.0.0.1:8080"
    cmd = ctx.calls[0][1]["cmd"]
    assert 'networksetup -setwebproxy "Ethernet" 10.0.0.1 8080' in cmd
    assert 'setsecurewebproxy "Ethernet" 10.0.0.1 8080' in cmd
    assert "setwebproxystate" in cmd and "setproxybypassdomains" in cmd


def test_install_ca_writes_pem_and_trusts_it():
    ctx = FakeContext()
    out = MacOSXModule().install_ca(ctx, cert_pem=b"-----BEGIN CERTIFICATE-----\nx\n", profile=None)
    assert out["ok"] and out["store"] == "System.keychain"
    assert ctx.written and ctx.written[0][0] == "/tmp/rvmc_ca.pem"
    cmd = ctx.calls[0][1]["cmd"]
    # non-root agent: through the golden's NOPASSWD sudoers line, exact argv
    assert (
        '[ "$(id -u)" = 0 ] || S="sudo -n"; $S /usr/bin/security add-trusted-cert -d -r trustRoot '
        "-k /Library/Keychains/System.keychain /tmp/rvmc_ca.pem"
    ) in cmd


def test_make_golden_steps_flag_the_gotchas():
    steps = " ".join(MacOSXModule().make_golden_steps())
    assert "OpenPartitionDxe" in steps  # APM DVD scan fix
    assert "NetworkInterfaces.plist" in steps  # network generalize (sysprep-equiv)
    assert "isa-applesmc" in steps


def test_tiger_install_ca_uses_certtool_into_x509anchors():
    """10.4 has no `security add-trusted-cert`; anchors go into X509Anchors via certtool, and a
    re-run skips an anchor that is already there (certtool fails on a duplicate)."""
    from vmctl_core.guestos.modules.mac_os_x import MacOSXTigerModule

    ctx = FakeContext(stdout="present\n")
    pem = b"-----BEGIN CERTIFICATE-----\nAAEC\nAwQF\n-----END CERTIFICATE-----\n"
    out = MacOSXTigerModule().install_ca(ctx, cert_pem=pem, profile=None)
    assert out["ok"] and out["store"] == "X509Anchors"
    assert ctx.written == [("/tmp/rvmc_ca.pem", pem)]
    cmd = ctx.calls[0][1]["cmd"]
    assert "certtool i /tmp/rvmc_ca.pem k=/System/Library/Keychains/X509Anchors" in cmd
    assert "grep -qF 'AAECAwQF'" in cmd
    assert "add-trusted-cert" not in cmd
    # Tiger's curl reads its own bundle, not the keychain: append once, guarded by a marker
    b = "/usr/share/curl/curl-ca-bundle.crt"
    assert f"[ -f {b} ] && ! grep -qF '# vmctl-ca " in cmd
    assert f"cat /tmp/rvmc_ca.pem; }} >> {b}" in cmd
