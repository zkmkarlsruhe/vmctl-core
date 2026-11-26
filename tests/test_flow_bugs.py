"""Regression tests for the cross-model-verified flow/correctness bugs.

Each test pins one HIGH-severity defect so a re-introduction fails loudly:
  bug 1 — capture BPF exclude spliced unquoted into `sh -c` -> shell syntax error
  bug 2 — PPC undefine() tears down the host tap even when `virsh undefine` FAILED
  bug 3 — create_ppc_tap() leaves a half-created tap + trusts a merely-present tap
  bug 4 — pack_bundle_zip() packs the output zip into itself on in-dir re-export
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import types
import zipfile
from pathlib import Path

import pytest

import vmctl_core.clone as clone_mod
from vmctl_core import capture, promotion
from vmctl_core.backends.base import BackendError
from vmctl_core.backends.libvirt_backend import LibvirtBackend
from vmctl_core.clone import CloneError, create_ppc_tap
from vmctl_core.plugins import PluginRegistry, load_plugins
from vmctl_core.plugins.spec import PluginClaim
from vmctl_core.router.router import claims_overlap


def _ns(returncode: int, stdout: str = "", stderr: str = "") -> types.SimpleNamespace:
    return types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


# --- bug 1: capture BPF exclude must not shell-syntax-error --------------------
class _FakeProc:
    def poll(self):
        return None


def test_capture_bpf_exclude_is_positional_and_shell_safe(tmp_path, monkeypatch):
    captured: dict = {}

    def fake_popen(argv, **kw):
        captured["argv"] = argv
        return _FakeProc()

    monkeypatch.setattr(capture.subprocess, "Popen", fake_popen)
    mon = capture.NetworkMonitor(tmp_path)
    mon.start("iid1", "tap0", exclude="tcp port 9009")
    monkeypatch.undo()  # restore the real subprocess.Popen for the sh -n check below

    argv = captured["argv"]
    assert argv[:4] == ["sudo", "-n", "sh", "-c"]
    script = argv[4]
    assert argv[5] == "sh"  # $0 for the -c script
    # BPF is a POSITIONAL arg and stands ALONE (no base filter precedes it), so it must
    # be `not ( ... )` — a leading `and` would be a binary op with no left operand and
    # fail libpcap pcap_compile.
    bpf = argv[6]
    assert bpf == "not ( tcp port 9009 )"

    # the grouping parens must NOT be spliced into the script text (that was the first
    # bug: `sh -c` parsed `( ... )` as a subshell -> 'Syntax error: "(" unexpected').
    assert "(" not in script and "not" not in script
    assert '"$@"' in script
    # the script itself is syntactically valid (parse-only, -n does not execute).
    assert subprocess.run(["sh", "-nc", script]).returncode == 0

    # the BPF must actually COMPILE (the second bug: a leading `and` execs tcpdump but
    # fails pcap_compile -> empty pcap, the same silent-no-capture symptom). Verify the
    # filter expression parses via tcpdump against an empty pcap; skip if tcpdump absent.
    if shutil.which("tcpdump"):
        empty = tmp_path / "empty.pcap"
        empty.write_bytes(
            b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xff\xff\x00\x00\x01\x00\x00\x00"
        )
        compiled = subprocess.run(
            ["tcpdump", "-r", str(empty), bpf], capture_output=True, text=True
        )
        assert "syntax error" not in compiled.stderr.lower(), compiled.stderr


def test_capture_no_exclude_appends_no_filter(tmp_path, monkeypatch):
    captured: dict = {}

    def fake_popen(argv, **kw):
        captured["argv"] = argv
        return _FakeProc()

    monkeypatch.setattr(capture.subprocess, "Popen", fake_popen)
    mon = capture.NetworkMonitor(tmp_path)
    mon.start("iid2", "tap0")
    # sudo -n sh -c <script> sh   (no trailing BPF word)
    assert captured["argv"][-1] == "sh"
    assert len(captured["argv"]) == 6


# --- bug 5/6: stop() targets the recorded root pid, keeps pidfile if it survives --
class _StopProc:
    def __init__(self, wait_raises: bool):
        self._wait_raises = wait_raises

    def poll(self):
        return None

    def wait(self, timeout=None):
        if self._wait_raises:
            raise subprocess.TimeoutExpired("sudo", timeout)
        return 0

    def kill(self):
        pass


def test_stop_kills_recorded_pid_via_sudo_and_clears_pidfile(tmp_path, monkeypatch):
    mon = capture.NetworkMonitor(tmp_path)
    iid = "c1"
    pidfile = mon._pidfile(iid)
    mypid = str(os.getpid())  # a genuinely-alive pid so is_capturing() isn't confounded
    pidfile.write_text(mypid + "\n")
    mon._procs[iid] = _StopProc(wait_raises=False)  # SIGTERM reaps it (wait returns)

    calls: list[list[str]] = []
    monkeypatch.setattr(capture.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or _ns(0))
    mon.stop(iid)
    # kills the RECORDED root pid via sudo (not proc.kill of the sudo wrapper)
    assert ["sudo", "-n", "kill", mypid] in calls
    assert not pidfile.exists()  # proc.wait proved it dead -> pidfile cleared


def test_stale_pidfile_is_not_capturing_and_never_killed(tmp_path, monkeypatch):
    """After a reboot the pidfile's number may belong to an unrelated process: only a
    pid whose argv carries ``-w <pcap>`` counts as our capture."""
    mon = capture.NetworkMonitor(tmp_path)
    iid = "c3"
    pidfile = mon._pidfile(iid)
    pcap = mon.pcap_path(iid)
    live = subprocess.Popen(["sh", "-c", "sleep 30", "sh", "-w", str(pcap)])
    try:
        pidfile.write_text(f"{live.pid}\n")
        assert mon.is_capturing(iid)
    finally:
        live.kill()
        live.wait()
    pidfile.write_text(f"{os.getpid()}\n")  # alive, but not a tcpdump for this pcap
    assert not mon.is_capturing(iid)
    assert not pidfile.exists()
    # stop() on the reconcile path (no Popen handle) must not sudo-kill the stranger
    pidfile.write_text(f"{os.getpid()}\n")
    calls: list[list[str]] = []
    monkeypatch.setattr(capture.subprocess, "run", lambda cmd, **kw: calls.append(cmd) or _ns(0))
    mon.stop(iid)
    assert calls == []
    assert not pidfile.exists()


def test_stop_keeps_pidfile_when_tcpdump_survives_the_kill(tmp_path, monkeypatch):
    mon = capture.NetworkMonitor(tmp_path)
    iid = "c2"
    pidfile = mon._pidfile(iid)
    mypid = str(os.getpid())
    pidfile.write_text(mypid + "\n")
    mon._procs[iid] = _StopProc(wait_raises=True)  # SIGTERM did NOT reap it
    # both kill and the kill -9 fallback fail (EPERM/sudoers)
    monkeypatch.setattr(capture.subprocess, "run", lambda cmd, **kw: _ns(1, stderr="EPERM"))
    mon.stop(iid)
    # not proven dead -> pidfile KEPT so is_capturing() stays True and start() won't
    # double-write the pcap
    assert pidfile.exists()
    assert mon.is_capturing(iid)


# --- snapshot overwrite: delete only the one name, never its children ---------
def test_snapshot_create_overwrite_keeps_children(monkeypatch):
    b = LibvirtBackend("d")
    calls: list[tuple[str, ...]] = []

    def fake_virsh(*a, **k):
        calls.append(a)
        if a[0] == "snapshot-list":
            return _ns(0, stdout="ready\nstep1\n")
        if a[0] == "dumpxml":
            return _ns(0, stdout="<domain><os><type arch='x86_64'>hvm</type></os></domain>")
        return _ns(0)

    b._virsh = fake_virsh  # type: ignore[method-assign]
    b.snapshot_create("ready")
    assert ("snapshot-delete", "d", "ready") in calls
    assert ("snapshot-create-as", "d", "ready", "--atomic") in calls
    assert not any("--children" in a for a in calls)


def test_snapshot_create_disk_only_on_running_domain_is_refused():
    """`--disk-only` on a running domain makes an EXTERNAL snapshot nobody tracks."""
    b = LibvirtBackend("d")
    calls: list[tuple[str, ...]] = []

    def fake_virsh(*a, **k):
        calls.append(a)
        if a[0] == "snapshot-list":
            return _ns(0, stdout="")
        if a[0] == "domstate":
            return _ns(0, stdout="running\n")
        return _ns(0, stdout="<domain><os><type arch='x86_64'>hvm</type></os></domain>")

    b._virsh = fake_virsh  # type: ignore[method-assign]
    with pytest.raises(BackendError, match="always includes RAM"):
        b.snapshot_create("x", memory=False)
    assert not any(a[0] == "snapshot-create-as" for a in calls)


# --- bug 2: undefine() keeps the tap when virsh undefine failed ----------------
def _ppc_backend(monkeypatch, undefine_rc: int) -> list[str]:
    b = LibvirtBackend("d")
    b._ppc_tap = lambda: "os9abcd12"  # type: ignore[method-assign]
    b._virsh = lambda *a, **k: _ns(undefine_rc, stderr="boom" if undefine_rc else "")  # type: ignore[method-assign]
    deleted: list[str] = []
    monkeypatch.setattr(clone_mod, "delete_ppc_tap", lambda t: deleted.append(t))
    b.undefine()
    return deleted


def test_undefine_keeps_tap_on_failed_undefine(monkeypatch):
    assert _ppc_backend(monkeypatch, undefine_rc=1) == []  # domain still defined -> tap kept


def test_undefine_deletes_tap_on_success(monkeypatch):
    assert _ppc_backend(monkeypatch, undefine_rc=0) == ["os9abcd12"]


# --- bug 3: create_ppc_tap cleanup + no fail-open on a merely-present tap -------
def test_create_ppc_tap_cleans_up_on_partial_failure(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:5] == ["ip", "-d", "-o", "link", "show"]:
            return _ns(1)  # _tap_ready probe: not ready
        if cmd[:3] == ["ip", "link", "show"]:
            return _ns(1)  # bare existence probe: not present
        if "tuntap" in cmd:
            return _ns(0)  # add succeeds
        if cmd[-1] == "up":
            return _ns(1, stderr="link up failed")  # bring-up FAILS after add
        return _ns(0)

    monkeypatch.setattr(clone_mod, "_run", fake_run)
    with pytest.raises(CloneError):
        create_ppc_tap("os9deadbe")
    # the half-created tap (add ok, up failed) must be torn down, not left behind
    assert ["sudo", "ip", "link", "del", "os9deadbe"] in calls


def test_create_ppc_tap_noop_only_when_up_and_enslaved(monkeypatch):
    calls: list[list[str]] = []

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:5] == ["ip", "-d", "-o", "link", "show"]:
            return _ns(
                0,
                stdout="9: os9x: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 master virbr0 state UP bridge_slave isolated on",
            )
        return _ns(0)

    monkeypatch.setattr(clone_mod, "_run", fake_run)
    create_ppc_tap("os9x")
    # fully-ready tap -> idempotent no-op, no privileged plumbing attempted
    assert not any(c and c[0] == "sudo" for c in calls)


def test_create_ppc_tap_recreates_a_present_but_down_tap(monkeypatch):
    calls: list[list[str]] = []
    state = {"ready": False}

    def fake_run(cmd):
        calls.append(cmd)
        if cmd[:5] == ["ip", "-d", "-o", "link", "show"]:
            # down/unbridged until enslave completes
            if state["ready"]:
                return _ns(
                    0, stdout="9: os9y: <UP,LOWER_UP> master virbr0 bridge_slave isolated on"
                )
            return _ns(0, stdout="9: os9y: <BROADCAST,MULTICAST> mtu 1500 state DOWN")
        if cmd[:3] == ["ip", "link", "show"]:
            return _ns(0)  # present
        if "isolated" in cmd:
            state["ready"] = True
            return _ns(0)
        return _ns(0)

    monkeypatch.setattr(clone_mod, "_run", fake_run)
    create_ppc_tap("os9y")
    # a present-but-down tap must be deleted before recreate (no fail-open)
    assert ["sudo", "ip", "link", "del", "os9y"] in calls
    assert any("tuntap" in c for c in calls)  # and then actually recreated


# --- bug 4: pack_bundle_zip must not pack the output zip into itself -----------
def _plugin_bundle(root):
    b = root / "sample-work-1.0.0"
    (b / "plugin").mkdir(parents=True)
    (b / "plugin" / "plugin.py").write_text("def setup(registry): pass\n")
    promotion.write_yaml(
        b / promotion.BUNDLE_YAML,
        {"bundle_format": promotion.BUNDLE_FORMAT, "plugin": {"id": "sample-work"}},
    )
    promotion.write_checksums(b)
    return b


def test_pack_excludes_output_zip_living_inside_bundle_dir(tmp_path):
    b = _plugin_bundle(tmp_path)
    out_zip = b / "export.zip"
    out_zip.write_bytes(b"stale-prior-export")  # simulate an in-dir re-export

    promotion.pack_bundle_zip(b, out_zip)

    with zipfile.ZipFile(out_zip) as z:
        names = z.namelist()
        assert z.testzip() is None  # archive is not corrupt
    # the target zip must never appear as a payload entry inside itself
    assert not any(n.endswith("export.zip") for n in names)

    dest = promotion.unpack_bundle_zip(out_zip, tmp_path / "unpacked")
    assert promotion.verify_bundle(dest)["ok"] is True


# --- bug 10: reload replaces a plugin's registrations, never accumulates -------
_ACCUM_PLUGIN = """\
def setup(registry):
    registry.register_web_handler(lambda path: None)
    registry.register_request_handler(lambda req: None)
    registry.register_startup_hook(lambda: None)
"""

_BROKEN_PLUGIN = """\
def setup(registry):
    registry.register_web_handler(lambda path: None)
    raise RuntimeError("setup blew up after a partial registration")
"""


def _write_plugin(root: Path, pid: str, body: str) -> None:
    d = root / pid
    d.mkdir(parents=True, exist_ok=True)
    (d / "manifest.yaml").write_text(f"id: {pid}\nname: {pid}\nentrypoint: plugin.py\n")
    (d / "plugin.py").write_text(body)


def test_reload_does_not_accumulate_hooks(tmp_path):
    _write_plugin(tmp_path, "accum", _ACCUM_PLUGIN)
    reg = PluginRegistry()
    load_plugins(tmp_path, reg)
    load_plugins(tmp_path, reg)  # reload into the SAME registry
    load_plugins(tmp_path, reg)  # ...and again
    assert len(reg._web_handlers) == 1  # replaced, not accumulated (was 3)
    assert len(reg._request_handlers) == 1
    assert len(reg._startup_hooks) == 1
    assert len(reg.loaded) == 1  # loaded list de-dupes by id on reload


def test_failed_setup_rolls_back_partial_registration(tmp_path):
    _write_plugin(tmp_path, "boom", _BROKEN_PLUGIN)
    reg = PluginRegistry()
    load_plugins(tmp_path, reg)  # swallows the error, logs it
    # the web handler registered BEFORE the raise must be rolled back, not left dangling
    assert reg._web_handlers == []
    assert reg.loaded == []


# --- bug 11: claims_overlap matches claim_matches (empty=any) + method/path ----
def test_overlap_empty_ports_means_any():
    a = PluginClaim(host="h", ports=[], protocols=["http"])
    b = PluginClaim(host="h", ports=[80], protocols=["http"])
    assert claims_overlap(a, b)  # empty ports = any -> overlaps (was under-detected)


def test_overlap_disjoint_paths_do_not_conflict():
    a = PluginClaim(host="h", paths=["/api/*"])
    b = PluginClaim(host="h", paths=["/ui/*"])
    assert not claims_overlap(a, b)  # path-split plugins must not false-conflict


def test_overlap_disjoint_methods_do_not_conflict():
    a = PluginClaim(host="h", methods=["GET"])
    b = PluginClaim(host="h", methods=["POST"])
    assert not claims_overlap(a, b)


def test_overlap_same_method_case_insensitive():
    a = PluginClaim(host="h", methods=["get"])
    b = PluginClaim(host="h", methods=["GET"])
    assert claims_overlap(a, b)


def test_clear_owner_is_value_aware_on_shared_dict_key():
    # Two plugins register the SAME poll key; the later one owns the live value. Clearing
    # the first plugin's registrations (reload) must NOT evict the second's current value —
    # dict ownership removes a key only while it still maps to THAT plugin's object.
    reg = PluginRegistry()

    def a():
        return "A"

    def b():
        return "B"

    reg._current_owner = "aa"
    reg.register_poll_provider("shared", a)
    reg._current_owner = "bb"
    reg.register_poll_provider("shared", b)  # bb overrides -> bb owns the live value
    reg._current_owner = None
    assert reg.get_poll_value("shared") == "B"

    reg._clear_owner("aa")  # reloading aa must leave bb's provider intact
    assert reg.get_poll_value("shared") == "B"
    reg._clear_owner("bb")  # bb's own clear DOES remove it
    assert reg.get_poll_value("shared") == "none"


def test_capture_drops_tcpdump_privileges_to_the_controller_user(tmp_path, monkeypatch):
    """The pcap must be owned by the controller user, not tcpdump's default drop user
    (`tcpdump`), or purging the drive dir fails (lab host 2026-10-30)."""
    captured: dict = {}

    def fake_popen(argv, **kw):
        captured["argv"] = argv
        return _FakeProc()

    monkeypatch.setattr(capture.subprocess, "Popen", fake_popen)
    capture.NetworkMonitor(tmp_path).start("iid3", "tap0")
    me = pwd.getpwuid(os.getuid()).pw_name
    assert f"exec tcpdump -Z {me} -i tap0 " in captured["argv"][4]
