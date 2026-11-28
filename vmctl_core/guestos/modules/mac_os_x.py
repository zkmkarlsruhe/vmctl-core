"""Mac OS X (Intel) module — Snow Leopard 10.6 and neighbours.

The modern counterpart to :class:`MacOS9Module`. OS 9 is classic PPC with a
faceless MacPython VA1 agent; 10.6 is a full BSD/Darwin Unix. Its agent speaks VA1
over TCP 9009 on the libvirt NAT (macOS has no virtio driver). Everything here is
Unix run through the agent's ``run_shell`` tool:

* logs      -> ``/var/log/system.log`` / the agent log (READ_LOGS)
* trust     -> ``security add-trusted-cert`` into the System keychain (INSTALL_CA);
               Safari reads the system keychain, so no separate browser store
* proxy     -> ``networksetup -setwebproxy`` on the Ethernet service (CONFIGURE_PROXY)
* dialogs   -> ``osascript``/System Events (HANDLE_DIALOGS, best-effort)
* audio     -> ``osascript`` set-volume/unmute (AUDIO_SETUP)
* datalink  -> the universal host->guest CD, which macOS auto-mounts under /Volumes

Deliberately NOT declared:
* READ_EVENT_LOG   — Windows-only structured log.
* INSTALL_CA_BROWSER — the default browser (Safari) trusts the SYSTEM keychain, so
  INSTALL_CA already covers it; only a bundled Firefox would need its own NSS store.
* CONFIGURE_BROWSER — Safari uses the system proxy (CONFIGURE_PROXY) and 10.6
  predates HSTS entirely, with a TLS floor already at 1.0; there is no browser-only
  knob to harden beyond the system proxy + cert_profile below.
* PROVISION_DRIVERS — every device is in-box (vmware-svga, e1000); nothing to install.
* SET_RESOLUTION   — under the unaccelerated vmware-svga framebuffer (no QE/CI) the
  mode is fixed by OpenCore; 10.6 has no in-box scriptable resolution API that works.

The screenshot caveat lives in the agent, not here: guest ``screencapture`` cannot
grab a frame without QE/CI, so the host screenshots via QMP screendump.

``gate_by_agent`` strips AGENT + the agent-dependent caps (read_logs, install_ca,
configure_proxy, handle_dialogs) from a base baked ``agent:false``, leaving the
universal DATALINK_MOUNT + MAKE_GOLDEN, exactly like the OS 9 stub degrades.
"""

from __future__ import annotations

import hashlib

from vmctl_core.guestos.capabilities import Capabilities, Capability
from vmctl_core.guestos.contract import BaseGuestOSModule, CertProfile, LogRecord

# Where the snowleopard agent writes its own log (guest-agent/snowleopard plist).
_AGENT_LOG = "/tmp/sl_agent.log"
_SYSTEM_LOG = "/var/log/system.log"
# The macOS network service the golden's DHCP config is bound to (see the golden
# network-prep: NetworkInterfaces.plist deleted so the clone's NIC becomes en0,
# and the "Ethernet" service drives it). networksetup addresses it by this name.
_NET_SERVICE = "Ethernet"


class MacOSXModule(BaseGuestOSModule):
    os_labels: tuple[str, ...] = (
        "macos-10.6",
        "mac-os-x",
        "macosx",
        "osx",
        "snow-leopard",
        "snowleopard",
        "darwin",
    )
    display_name = "Mac OS X (Intel)"

    def caps(self) -> Capabilities:
        return Capabilities.of(
            Capability.AGENT,  # snowleopard agent, legacy-TCP :9009 over the NAT
            Capability.READ_LOGS,  # system.log / agent log via run_shell
            Capability.INSTALL_CA,  # security add-trusted-cert -> System keychain
            Capability.CERT_PROFILE,  # legacy TLS opinion (see cert_profile)
            Capability.CONFIGURE_PROXY,  # networksetup -setwebproxy
            Capability.HANDLE_DIALOGS,  # osascript / System Events (best-effort)
            Capability.AUDIO_SETUP,  # osascript set volume / unmute
            Capability.DATALINK_MOUNT,  # universal CD, auto-mounted at /Volumes
            Capability.MAKE_GOLDEN,
        )

    def agent_transport(self, ctx) -> str:
        # VA1 TCP :9009 on the libvirt NAT; macOS has no vioser driver.
        return "tcp"

    # --- helpers ------------------------------------------------------------
    def _sh(self, ctx, command: str, *, timeout: float = 30.0) -> dict:
        """Return decoded VA1 run_shell kv (exit, stdout, stderr, truncated)."""
        return ctx.guest_call("run_shell", cmd=command, timeout=timeout).kv

    # --- logs ---------------------------------------------------------------
    def read_logs(self, ctx, *, kind: str = "system", count: int = 50) -> list[LogRecord]:
        """Generic text logs via the agent.

        kinds:
          system -> tail of /var/log/system.log (the ASL text sink on 10.6).
          agent  -> the snowleopard agent's own stdout/err log (/tmp/sl_agent.log).
        """
        kind = (kind or "system").lower()
        path = _AGENT_LOG if kind == "agent" else _SYSTEM_LOG
        n = count if count and count > 0 else 50
        try:
            res = self._sh(ctx, f"tail -n {int(n)} {path} 2>/dev/null")
        except Exception as e:
            return [LogRecord(source=kind, level="warning", message=f"(unavailable: {e})")]
        out = res.get("stdout") or ""
        recs = [LogRecord(source=kind, message=ln) for ln in out.splitlines() if ln.strip()]
        return recs or [LogRecord(source=kind, message="(no log output)")]

    # --- trust / certs ------------------------------------------------------
    def cert_profile(self, ctx, *, probe=True) -> CertProfile:
        # 10.6 Secure Transport: SHA-256 leaf certs are fine (SHA-2 since 10.5), but
        # the TLS ceiling is 1.0 — TLS 1.1/1.2 only arrived in 10.9. So the MITM proxy
        # must be willing to speak legacy ciphers down to TLS 1.0 for this client.
        return CertProfile(
            name="legacy_sha2",
            leaf_hash="sha256",
            cipher_profile="legacy",
            tls_min="TLSv1",
            detail="macos-10.6: Secure Transport, SHA-256 ok, TLS 1.0 max (1.2 needs 10.9)",
        )

    def install_ca(self, ctx, *, cert_pem, profile, browser=True) -> dict:
        """Add a root CA to the System keychain (which Safari trusts). ``browser`` is
        accepted for contract parity but has no separate store on 10.6 (Safari = system
        keychain); a bundled Firefox NSS store is out of scope (INSTALL_CA_BROWSER off)."""
        guest_path = "/tmp/rvmc_ca.pem"
        # The 10.6 agent runs as `vmctl` (uid 501, a GUI LaunchAgent): the admin trust store
        # needs root ("SecCertificateAddToKeychain: Could not write to the file"). The golden
        # grants exactly this command line NOPASSWD in /etc/sudoers (vmctl-guest-agent
        # hygiene/README.md); `sudo -n` fails fast where that line is missing. Re-adding a
        # trusted root exits 0, so the call is idempotent.
        try:
            ctx.guest_write_file(guest_path, cert_pem)
            res = self._sh(
                ctx,
                'S=; [ "$(id -u)" = 0 ] || S="sudo -n"; '
                "$S /usr/bin/security add-trusted-cert -d -r trustRoot "
                f"-k /Library/Keychains/System.keychain {guest_path}",
                timeout=60.0,
            )
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {
            "ok": res.get("exit") == "0",
            "exit_code": int(res["exit"]),
            "stderr": res.get("stderr", ""),
            "store": "System.keychain",
        }

    # --- proxy --------------------------------------------------------------
    def configure_proxy(self, ctx, *, addr, bypass="") -> dict:
        """Point the system (and thus Safari) at the MITM proxy via networksetup on the
        Ethernet service. ``addr`` is host:port; sets both web and secure-web proxy."""
        host, _, port = str(addr).partition(":")
        port = port or "8080"
        cmds = [
            f'networksetup -setwebproxy "{_NET_SERVICE}" {host} {port}',
            f'networksetup -setsecurewebproxy "{_NET_SERVICE}" {host} {port}',
            f'networksetup -setwebproxystate "{_NET_SERVICE}" on',
            f'networksetup -setsecurewebproxystate "{_NET_SERVICE}" on',
        ]
        if bypass:
            domains = " ".join(bypass.replace(",", " ").split())
            cmds.append(f'networksetup -setproxybypassdomains "{_NET_SERVICE}" {domains}')
        try:
            res = self._sh(ctx, " && ".join(cmds))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": res.get("exit") == "0", "addr": f"{host}:{port}", "service": _NET_SERVICE}

    def clear_proxy(self, ctx) -> dict:
        cmds = [
            f'networksetup -setwebproxystate "{_NET_SERVICE}" off',
            f'networksetup -setsecurewebproxystate "{_NET_SERVICE}" off',
        ]
        try:
            res = self._sh(ctx, " && ".join(cmds))
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": res.get("exit") == "0", "service": _NET_SERVICE}

    # --- dialogs / audio / datalink ----------------------------------------
    def handle_dialogs(self, ctx, *, kind="security_warning") -> dict:
        """Best-effort dismiss of a frontmost dialog by pressing its default button via
        System Events. Requires GUI scripting; returns ok=False rather than raising if
        the AppleScript fails (e.g. no window server / assistive access off)."""
        script = 'tell application "System Events" to key code 36'  # key code 36 = Return
        try:
            res = self._sh(ctx, f"osascript -e '{script}'")
        except Exception as e:
            return {"ok": False, "error": str(e), "kind": kind}
        return {"ok": res.get("exit") == "0", "kind": kind, "action": "press-default"}

    def audio_setup(self, ctx) -> dict:
        """Unmute + raise the guest output volume (host sink wiring is the backend's job)."""
        script = "set volume output volume 100 without output muted"
        try:
            res = self._sh(ctx, f"osascript -e '{script}'")
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {"ok": res.get("exit") == "0"}

    def datalink_mount(self, ctx) -> dict:
        """The universal host->guest CD is inserted by the backend (ctx.insert_cd) and
        macOS auto-mounts it under /Volumes — nothing to mount in-guest. Report the
        current /Volumes entries so the caller can find the share."""
        try:
            res = self._sh(ctx, "ls -1 /Volumes 2>/dev/null")
        except Exception as e:
            return {"ok": False, "error": str(e)}
        vols = [v for v in (res.get("stdout") or "").splitlines() if v.strip()]
        return {
            "ok": True,
            "volumes": vols,
            "note": "macOS auto-mounts inserted CDs under /Volumes",
        }

    # --- golden recipe ------------------------------------------------------
    def make_golden_steps(self) -> list[str]:
        return [
            "boot OpenCore (with OpenPartitionDxe.efi enabled) + OVMF; attach the retail "
            "Snow Leopard install ISO as a disk (not a CD — the APM DVD is disk-scanned)",
            "-cpu Penryn,vendor=GenuineIntel + isa-applesmc,osk=<public 10.6 key>; q35, "
            "e1000 NIC, vmware-svga video (in-box driver -> real resolution, no QE/CI)",
            "install to a Mac OS Extended (Journaled) / GUID disk via Disk Utility; the "
            "vmctl macos-x86 guest type renders exactly this (Hardware.macos + aux OpenCore disk)",
            "create an admin account, enable autologin + Remote Login (sshd), and bake the "
            "snowleopard agent as a LaunchAgent (org.vmctl.rvmc-agent, RunAtLoad+KeepAlive) so "
            "it starts in the GUI session and serves TCP:9009; set the base agent:true",
            "GENERALIZE THE NETWORK before capture (sysprep-equivalent): delete "
            "/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist so a cloned NIC "
            "re-enumerates as en0 and inherits the DHCP service; else clones come up unconfigured",
            "hard-poweroff (clean shutdown panics in IOGraphicsFamily/vmware-svga; the HFS+ "
            "journal recovers on next boot)",
        ]


class MacOSXTigerModule(MacOSXModule):
    """Mac OS X 10.4 Tiger on ppc/mac99 (the osx-tiger golden). Same agent contract and
    behaviours as 10.6; only the label differs. Without it "mac-os-x-tiger" resolved to
    the Intel module by its "mac-os-x" prefix and the UI called a PowerPC guest Intel."""

    os_labels: tuple[str, ...] = ("mac-os-x-tiger", "osx-tiger", "tiger")
    display_name = "Mac OS X Tiger (PowerPC)"
    # 10.4.11's HID stack maps the usb-tablet range onto ~1.178x the 800x600 screen,
    # centred, then pins to the screen (measured 2026-10-13: raw QMP abs x=8192/24576
    # -> GetGlobalMouse 164/635, ideal 200/600; tracking speed has no effect; QEMU
    # VNC/HID deliver the exact raw values). Mac OS 9 on the same tablet is 1:1.
    abs_pointer_gain = 1.178

    def install_ca(self, ctx, *, cert_pem, profile, browser=True) -> dict:
        """10.4 has no ``security add-trusted-cert`` (10.5+). Its trust anchors are the
        X509Anchors keychain, which ``certtool i`` imports into; the Tiger agent is a root
        LaunchDaemon, so it may write there. ``certtool`` fails on a duplicate, so an anchor
        that is already present (same base64 body) is skipped.

        The system curl (7.16.3, OpenSSL 0.9.7l) ignores the keychain and verifies against
        its own ``/usr/share/curl/curl-ca-bundle.crt``, so the PEM is also appended there,
        once: a marker line carrying a hash of the PEM bodies guards the append."""
        guest_path = "/tmp/rvmc_ca.pem"
        anchors = "/System/Library/Keychains/X509Anchors"
        bundle = "/usr/share/curl/curl-ca-bundle.crt"
        text = cert_pem.decode("ascii", "replace")
        body = "".join(ln for ln in text.splitlines() if ln and not ln.startswith("-----"))
        marker = "# vmctl-ca " + hashlib.sha256(body.encode()).hexdigest()[:16]
        try:
            ctx.guest_write_file(guest_path, cert_pem)
            res = self._sh(
                ctx,
                f"if security find-certificate -a -p {anchors} | tr -d '\\n' "
                f"| grep -qF '{body}'; then echo present; "
                f"else certtool i {guest_path} k={anchors}; fi && "
                f"if [ -f {bundle} ] && ! grep -qF '{marker}' {bundle}; then "
                f"{{ echo; echo '{marker}'; cat {guest_path}; }} >> {bundle} "
                "&& echo 'curl bundle: appended'; fi",
                timeout=60.0,
            )
        except Exception as e:
            return {"ok": False, "error": str(e)}
        return {
            "ok": res.get("exit") == "0",
            "exit_code": int(res["exit"]),
            "stdout": (res.get("stdout") or "").strip()[-200:],
            "stderr": res.get("stderr", ""),
            "store": "X509Anchors",
        }
