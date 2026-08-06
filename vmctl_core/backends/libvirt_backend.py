"""libvirt VMBackend over ``virsh`` (default ``qemu:///system``).

Adapted, per-instance, from exhibition-vm-controller's ``vm_manager.py`` — we own
this copy. Each instance binds one libvirt domain. No sudo required when the user
is in the ``libvirt`` group and the URI is ``qemu:///system``.
"""

from __future__ import annotations

import base64
import contextlib
import ipaddress
import json
import os
import struct
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
import zlib

from .base import BackendError


def _read_ppm_token(buf: bytes, i: int) -> tuple[bytes, int]:
    """Read one whitespace-delimited header token from a PPM at offset ``i``,
    skipping leading whitespace and ``#`` comment lines. Returns (token, next_i)."""
    n = len(buf)
    while i < n:
        c = buf[i : i + 1]
        if c == b"#":  # comment runs to end of line
            while i < n and buf[i : i + 1] not in (b"\n", b"\r"):
                i += 1
        elif c.isspace():
            i += 1
        else:
            break
    start = i
    while i < n and not buf[i : i + 1].isspace():
        i += 1
    return buf[start:i], i


def ppm_to_png(ppm: bytes) -> bytes:
    """Convert a binary P6 PPM (what QMP/HMP ``screendump`` writes) to PNG, using
    only the stdlib (``zlib`` + manual chunking) so vmctl-core needs no image
    dependency. This is the arch-portable framebuffer path: the screamer-qemu PPC
    fork has no libpng, so ``virsh screenshot``/QMP ``screendump`` with a PNG
    target fails there, but the default PPM dump always works — we encode the PNG
    host-side instead of asking qemu to.

    Only 8-bit RGB (maxval 255) is supported, which is the format qemu emits.
    Raises :class:`BackendError` on any malformed / unsupported input."""
    if not ppm.startswith(b"P6"):
        head = ppm[:32]
        raise BackendError(f"not a P6 PPM (screendump gave {head!r})")
    tok_w, i = _read_ppm_token(ppm, 2)
    tok_h, i = _read_ppm_token(ppm, i)
    tok_max, i = _read_ppm_token(ppm, i)
    try:
        width, height, maxval = int(tok_w), int(tok_h), int(tok_max)
    except ValueError as e:
        raise BackendError(f"bad PPM header: {e}") from e
    if maxval != 255:
        raise BackendError(f"unsupported PPM maxval {maxval} (only 8-bit/255)")
    # exactly one whitespace byte separates the header from the raster
    data = ppm[i + 1 :]
    stride = width * 3
    expected = stride * height
    if len(data) < expected:
        raise BackendError(f"truncated PPM raster: {len(data)} < {expected} bytes")
    data = data[:expected]

    # PNG scanlines: each row is prefixed with a filter-type byte (0 = none).
    raw = bytearray()
    for y in range(height):
        raw.append(0)
        raw.extend(data[y * stride : (y + 1) * stride])

    def _chunk(tag: bytes, payload: bytes) -> bytes:
        return (
            struct.pack(">I", len(payload))
            + tag
            + payload
            + struct.pack(">I", zlib.crc32(tag + payload) & 0xFFFFFFFF)
        )

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)  # 8-bit, colour type 2 (RGB)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", zlib.compress(bytes(raw), 6))
        + _chunk(b"IEND", b"")
    )


class LibvirtBackend:
    """A VMBackend bound to a single libvirt domain."""

    def __init__(self, name: str, uri: str = "qemu:///system") -> None:
        self.name = name
        self.uri = uri

    # --- virsh plumbing ---------------------------------------------------
    def _virsh(
        self, *args: str, timeout: float = 30.0, check: bool = True
    ) -> subprocess.CompletedProcess:
        cmd = ["virsh", "-c", self.uri, *args]
        # Force the C locale: stop()/get_settings() and the state parsers key off
        # English virsh output ("not running", "Max memory", "Autostart"); under a
        # localized LANG those substring checks silently break (stop() would raise on
        # an already-stopped domain; get_settings() would return defaults).
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if check and p.returncode != 0:
            raise BackendError(f"virsh {' '.join(args)} failed: {p.stderr.strip()}")
        return p

    def _agent(self, payload: dict, timeout: float = 15.0) -> dict:
        """Run a qemu-agent-command and return the parsed ``return`` value."""
        p = self._virsh("qemu-agent-command", self.name, json.dumps(payload), timeout=timeout)
        return json.loads(p.stdout).get("return")

    # --- existence & state ------------------------------------------------
    def exists(self) -> bool:
        return self._virsh("dominfo", self.name, check=False).returncode == 0

    def state(self) -> str:
        p = self._virsh("domstate", self.name, check=False)
        return p.stdout.strip() if p.returncode == 0 else "undefined"

    def is_running(self) -> bool:
        return self.state() == "running"

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        if self.is_running():
            return
        self._virsh("start", self.name)
        self._flush_conntrack()

    def stop(self) -> None:
        p = self._virsh("destroy", self.name, check=False)
        if p.returncode != 0 and "not running" not in (p.stderr or "").lower():
            raise BackendError(f"destroy failed: {p.stderr.strip()}")

    def shutdown(self) -> None:
        self._virsh("shutdown", self.name, check=False)

    def reboot(self) -> None:
        # graceful: needs ACPI in the guest (or the guest agent)
        self._virsh("reboot", self.name, check=False)

    def reset(self) -> None:
        # hard power-cycle, no clean shutdown
        self._virsh("reset", self.name, check=False)

    # --- settings ---------------------------------------------------------
    def get_settings(self) -> dict:
        out = self._virsh("dominfo", self.name).stdout
        info: dict = {}
        for line in out.splitlines():
            k, _, v = line.partition(":")
            info[k.strip()] = v.strip()
        mem_kib = int((info.get("Max memory", "0").split() or ["0"])[0] or 0)
        return {
            "memory_mb": mem_kib // 1024,
            "vcpus": int(info.get("CPU(s)", "0") or 0),
            "autostart": info.get("Autostart", "disable") == "enable",
            "state": info.get("State", "unknown"),
            "persistent": info.get("Persistent", "no") == "yes",
        }

    def set_settings(
        self,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        autostart: bool | None = None,
    ) -> None:
        if memory_mb is not None:
            kib = str(int(memory_mb) * 1024)
            # raise the ceiling first, then the allocation (persistent config)
            self._virsh("setmaxmem", self.name, kib, "--config")
            self._virsh("setmem", self.name, kib, "--config")
        if vcpus is not None:
            n = str(int(vcpus))
            self._virsh("setvcpus", self.name, n, "--config", "--maximum")
            self._virsh("setvcpus", self.name, n, "--config")
        if autostart is not None:
            args = ["autostart", self.name] + ([] if autostart else ["--disable"])
            self._virsh(*args, check=False)

    def tap_interface(self) -> str | None:
        p = self._virsh("domiflist", self.name, check=False)
        for line in p.stdout.splitlines()[2:]:
            iface = (line.split() or [""])[0]
            if iface.startswith("vnet"):
                return iface
        # ppc/mac99: the NIC is a raw qemu:commandline `-netdev tap,...,ifname=os9<h>`
        # device libvirt's domiflist never lists (it doesn't know the cmdline NIC
        # exists). Fall back to the host-managed tap parsed from the domain XML so
        # network capture works on the real tap for a ppc guest (research/64).
        return self._ppc_tap()

    # --- domain definition ------------------------------------------------
    def define(self, xml_path: str) -> None:
        self._virsh("define", xml_path)

    def dumpxml(self) -> str:
        """The live/persistent domain XML."""
        return self._virsh("dumpxml", self.name).stdout

    # dnsmasq lease DB for the libvirt NAT bridge. The ppc/mac99 raw-cmdline sungem
    # NIC is invisible to `virsh domifaddr` (libvirt doesn't know the qemu:commandline
    # NIC exists), so for ppc we resolve the lease by matching this file on the MAC.
    DNSMASQ_STATUS = "/var/lib/libvirt/dnsmasq/virbr0.status"

    # Isolated host-only management network (containment for the legacy-TCP agent
    # transport; see deploy/networks/rvmc-mgmt.xml + Hardware.mgmt_nic). When a domain
    # carries a NIC on MGMT_NETWORK, guest_ip() returns ONLY an address inside
    # MGMT_SUBNET so the controller/tcp_helper dial the isolated :9009, never the
    # artwork NIC. Guests without a mgmt NIC keep the original first-lease behaviour.
    MGMT_NETWORK = "rvmc-mgmt"
    MGMT_SUBNET = ipaddress.IPv4Network("10.77.0.0/24")

    def _domain_arch(self) -> str | None:
        """The domain's OS arch (e.g. 'ppc', 'x86_64') from its XML, or None."""
        try:
            root = ET.fromstring(self.dumpxml())
            t = root.find("./os/type")
            return t.get("arch") if t is not None else None
        except (BackendError, ET.ParseError):
            return None

    def _is_ppc(self) -> bool:
        """True for a ppc/mac99 (Mac OS 9) domain. Several virsh sub-features behave
        differently on the screamer-qemu PPC fork (no --atomic snapshots, no managed
        CD device, cmdline-only NIC) so they branch on this."""
        return (self._domain_arch() or "").startswith("ppc")

    def _domain_macs(self) -> list[str]:
        """All MACs declared for this domain — both managed <interface> MACs AND the
        ppc raw `-device sungem,mac=...` cmdline NIC (which has no <interface>)."""
        macs: list[str] = []
        try:
            root = ET.fromstring(self.dumpxml())
        except (BackendError, ET.ParseError):
            return macs
        for m in root.findall("./devices/interface/mac"):
            addr = m.get("address")
            if addr:
                macs.append(addr.lower())
        # qemu:commandline sungem NIC: ...<qemu:arg value='sungem,netdev=net0,mac=XX'/>
        ns = "http://libvirt.org/schemas/domain/qemu/1.0"
        for arg in root.findall(f"./{{{ns}}}commandline/{{{ns}}}arg"):
            val = arg.get("value") or ""
            if "sungem" in val and "mac=" in val:
                macs.append(val.split("mac=", 1)[1].split(",")[0].strip().lower())
        return macs

    def _ip_from_dnsmasq(self, macs: list[str]) -> str | None:
        """Resolve an IPv4 lease for any of `macs` from libvirt's dnsmasq status DB.
        The fallback for the ppc cmdline NIC that domifaddr cannot see."""
        if not macs:
            return None
        want = {m.lower() for m in macs}
        try:
            with open(self.DNSMASQ_STATUS) as f:
                leases = json.load(f)
        except (OSError, json.JSONDecodeError):
            return None
        for lease in leases:
            mac = str(lease.get("mac-address", "")).lower()
            ip = lease.get("ip-address", "")
            if mac in want and ip and ip.count(".") == 3 and not ip.startswith("127."):
                return ip
        return None

    def _has_mgmt_nic(self) -> bool:
        """True when the domain carries a NIC on the isolated MGMT_NETWORK (the
        legacy-TCP containment NIC — Hardware.mgmt_nic). Guests with one get their
        guest_ip() resolved on the mgmt subnet only.

        Raises (does NOT return False) on a dumpxml/parse ERROR: a transient dumpxml
        failure is not evidence of "no mgmt NIC", and swallowing it would misclassify a
        contained dual-NIC guest as single-NIC and hand its artwork-NIC lease to the
        control plane (containment fails OPEN). Callers catch the error and fail CLOSED."""
        root = ET.fromstring(self.dumpxml())
        for src in root.findall("./devices/interface/source"):
            if src.get("network") == self.MGMT_NETWORK:
                return True
        return False

    def guest_ip(self) -> str | None:
        """Best-effort guest IPv4 (DHCP lease / ARP) — for reaching a TCP in-guest
        agent on guests without virtio-serial (e.g. pristine XP on rtl8139, or the
        ppc/mac99 mac9 agent on its raw sungem NIC).

        When the domain has an isolated management NIC (Hardware.mgmt_nic => a NIC on
        MGMT_NETWORK), this returns ONLY an address inside MGMT_SUBNET (10.77.0.0/24)
        so the controller/tcp_helper dial the contained :9009 and never fall back to
        the artwork/NAT NIC. If the mgmt lease is not up yet it returns None (the
        caller should retry) rather than leaking the artwork IP. Guests without a mgmt
        NIC keep the original behaviour: the first non-loopback lease/ARP/agent addr."""
        # ppc/mac99: the sungem NIC is a raw qemu:commandline device that libvirt's
        # domifaddr is blind to. Resolve the lease directly from dnsmasq by MAC.
        if self._domain_arch() == "ppc":
            return self._ip_from_dnsmasq(self._domain_macs())
        try:
            prefer_mgmt = self._has_mgmt_nic()
        except (BackendError, ET.ParseError):
            # Can't read the domain's NIC topology -> fail CLOSED (return None so the
            # caller retries) rather than defaulting to single-NIC and leaking the
            # artwork lease to the control plane.
            return None
        for src in ("lease", "arp", "agent"):
            p = self._virsh("domifaddr", self.name, "--source", src, check=False)
            for line in p.stdout.splitlines():
                for tok in line.split():
                    if tok.count(".") == 3 and "/" in tok:
                        ip = tok.split("/")[0]
                        if ip.startswith("127."):
                            continue
                        if prefer_mgmt:
                            # Containment: only accept the isolated mgmt subnet. Never
                            # return the artwork NIC lease for a mgmt-NIC guest.
                            try:
                                if ipaddress.ip_address(ip) in self.MGMT_SUBNET:
                                    return ip
                            except ValueError:
                                pass
                            continue
                        return ip
        return None

    def _leases(self) -> list[str]:
        """Every non-loopback IPv4 the domain has (lease/ARP/agent, dnsmasq for ppc), in
        discovery order. The raw material control_ip()/artwork_ip() split by subnet."""
        if self._domain_arch() == "ppc":
            ip = self._ip_from_dnsmasq(self._domain_macs())
            return [ip] if ip else []
        out: list[str] = []
        for src in ("lease", "arp", "agent"):
            p = self._virsh("domifaddr", self.name, "--source", src, check=False)
            for line in p.stdout.splitlines():
                for tok in line.split():
                    if tok.count(".") == 3 and "/" in tok:
                        ip = tok.split("/")[0]
                        if not ip.startswith("127.") and ip not in out:
                            out.append(ip)
        return out

    def control_ip(self) -> str | None:
        """The IP the CONTROL plane (agent transport: tcp_helper / raw-TCP / poll) dials.

        On a dual-homed guest with an isolated control NIC (Hardware.mgmt_nic on
        MGMT_NETWORK) this is the mgmt-subnet (10.77.0.0/24) lease; on a single-NIC guest
        it is the sole lease. Never the artwork NIC on a control-NIC guest. Same policy as
        the legacy guest_ip(), named for its actual role. None if the mgmt lease isn't up."""
        leases = self._leases()
        try:
            has_mgmt = self._has_mgmt_nic()
        except (BackendError, ET.ParseError):
            # dumpxml/parse failed: can't tell single- from dual-NIC, so fail CLOSED
            # rather than hand leases[0] (possibly the artwork NIC) to the control plane.
            return None
        if has_mgmt:
            for ip in leases:
                with contextlib.suppress(ValueError):
                    if ipaddress.ip_address(ip) in self.MGMT_SUBNET:
                        return ip
            return None
        return leases[0] if leases else None

    def artwork_ip(self) -> str | None:
        """The IP the DATA plane sees for this guest — the artwork NIC. On a control-NIC
        guest this is the NON-mgmt lease (so source-IP->project mapping, dnsmasq and the
        router key on the artwork interface, NOT the isolated control NIC — the codex
        split-brain guard). On a single-NIC guest it is the sole lease. None until a
        non-mgmt lease is visible."""
        leases = self._leases()
        try:
            has_mgmt = self._has_mgmt_nic()
        except (BackendError, ET.ParseError):
            # dumpxml/parse failed: can't tell whether a lease is the artwork NIC or the
            # isolated mgmt NIC, so fail CLOSED rather than risk routing the mgmt IP.
            return None
        if has_mgmt:
            for ip in leases:
                with contextlib.suppress(ValueError):
                    if ipaddress.ip_address(ip) not in self.MGMT_SUBNET:
                        return ip
            return None
        return leases[0] if leases else None

    def define_xml(self, xml: str) -> None:
        """Validate + redefine the persistent config from an XML string.
        (Rewrites the inactive definition; a running domain keeps its current
        devices until next boot.)"""
        import tempfile

        fd, path = tempfile.mkstemp(suffix=".xml")
        try:
            os.write(fd, xml.encode("utf-8"))
            os.close(fd)
            # best-effort schema check (won't fail the call if the tool is absent).
            # A missing binary raises FileNotFoundError from exec — NOT a "command not
            # found" line in stderr — so catch it explicitly and skip validation.
            try:
                v = subprocess.run(["virt-xml-validate", path], capture_output=True, text=True)
            except FileNotFoundError:
                v = None
            if v is not None and v.returncode != 0:
                raise BackendError(f"invalid domain XML: {v.stderr.strip() or v.stdout.strip()}")
            self._virsh("define", path)
        finally:
            with contextlib.suppress(OSError):
                os.remove(path)

    def _ppc_tap(self) -> str | None:
        """The per-instance host-managed tap of a ppc/mac99 domain, read from the
        `-netdev tap,...,ifname=<tap>` qemu:commandline arg. None for x86 domains
        (libvirt owns their tap) or if the domain has no such NIC."""
        try:
            root = ET.fromstring(self.dumpxml())
        except (BackendError, ET.ParseError):
            return None
        ns = "http://libvirt.org/schemas/domain/qemu/1.0"
        for arg in root.findall(f"./{{{ns}}}commandline/{{{ns}}}arg"):
            val = arg.get("value") or ""
            if val.startswith("tap,") and "ifname=" in val:
                return val.split("ifname=", 1)[1].split(",")[0].strip()
        return None

    def undefine(self) -> None:
        # Capture the ppc tap BEFORE the definition is gone, then clean it up after
        # undefine. x86 domains have no host-managed tap here => _ppc_tap() is None.
        tap = self._ppc_tap()
        # --snapshots-metadata so internal snapshots don't block the undefine
        p = self._virsh("undefine", self.name, "--snapshots-metadata", check=False)
        # Tear the host tap down ONLY if the domain is actually gone. A failed undefine
        # (domain still defined — e.g. running, or a virsh error) must keep its NIC:
        # ripping the tap out from under a still-defined/running ppc guest kills its
        # networking with no way back short of a re-clone.
        if tap and p.returncode == 0:
            # local import: clone owns the tap lifecycle (create on clone, delete here)
            from ..clone import delete_ppc_tap

            delete_ppc_tap(tap)

    # --- snapshots --------------------------------------------------------
    def snapshot_list(self) -> list[str]:
        p = self._virsh("snapshot-list", self.name, "--name")
        return [s.strip() for s in p.stdout.splitlines() if s.strip()]

    def snapshot_create(self, name: str, *, memory: bool = True) -> None:
        # Overwrite an existing snapshot of the same name (and its children).
        if name in self.snapshot_list():
            self._virsh("snapshot-delete", self.name, name, "--children", check=False)
        args = ["snapshot-create-as", self.name, name]
        # --atomic is unsupported on the screamer-qemu PPC fork (mac99) — virsh
        # rejects it there. x86/KVM keeps the atomic guarantee; ppc takes the plain
        # (still internal, single-domain) create. research/64.
        if not self._is_ppc():
            args.append("--atomic")
        # Internal snapshot. When the domain is running this captures RAM too
        # (exact-moment revert). disk-only is the crash-consistent fallback.
        if not memory and self.is_running():
            args.append("--disk-only")
        self._virsh(*args, timeout=120.0)

    def snapshot_revert(self, name: str) -> None:
        self._virsh("snapshot-revert", self.name, name, timeout=120.0)
        self._flush_conntrack()

    def snapshot_delete(self, name: str) -> None:
        self._virsh("snapshot-delete", self.name, name)

    # --- screen -----------------------------------------------------------
    def screenshot(self, screen: int = 0) -> bytes:
        """PNG bytes of a display head, captured with no guest cooperation.

        Arch-portable: it does NOT use ``virsh screenshot``. That path asks qemu
        to emit a PNG, which the screamer-qemu PPC fork (mac99 / Mac OS 9, Mac OS
        X Tiger, Snow Leopard) cannot do — that build has no libpng, so qemu
        answers ``Enable PNG support with libpng for screendump`` and the capture
        fails. The agent-independent QMP backstop must work on exactly those
        guests, so instead we drive the monitor's ``screendump`` to a temp PPM
        (the default framebuffer dump — no libpng needed, works on every arch) and
        encode the PNG host-side. x86 goldens take the identical path.

        Returns valid PNG bytes on both x86 (win7, …) and ppc (mac9, tiger, …)
        goldens. Raises :class:`BackendError` if the build genuinely cannot dump
        the framebuffer (surfaced by ``qmp_backstop`` as a structured error rather
        than a traceback)."""
        fd, tmp = tempfile.mkstemp(suffix=".ppm", prefix="vmshot_")
        os.close(fd)
        # Let qemu (re)create the file under its own uid/umask; a pre-existing
        # 0600 file we own could block qemu's open() when it runs as another user.
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        try:
            # HMP ``screendump <file>`` with no format arg always writes a PPM of
            # display head 0. Every golden in the fleet is single-head, so the
            # ``screen`` arg (kept for API parity) does not select a device here.
            p = self._virsh(
                "qemu-monitor-command", self.name, "--hmp", f"screendump {tmp}", timeout=20.0
            )
            # HMP reports failures on stdout (not via exit code), e.g. an open
            # error or a build that rejects screendump — treat a missing/short
            # file as the failure signal and surface the monitor's message.
            try:
                with open(tmp, "rb") as f:
                    ppm = f.read()
            except OSError as e:
                msg = (p.stdout or p.stderr or "").strip()
                raise BackendError(
                    f"screendump produced no output for {self.name}" + (f": {msg}" if msg else "")
                ) from e
            return ppm_to_png(ppm)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(tmp)

    def vnc_endpoint(self) -> tuple[str, int] | None:
        p = self._virsh("vncdisplay", self.name, check=False)
        disp = p.stdout.strip()
        if p.returncode != 0 or not disp:
            return None
        # forms: ':0', '127.0.0.1:0', 'host:0'
        host, _, num = disp.rpartition(":")
        host = host or "127.0.0.1"
        if host in ("", "0.0.0.0"):
            host = "127.0.0.1"
        try:
            return host, 5900 + int(num)
        except ValueError:
            return None

    def send_key(self, keys: list[str]) -> None:
        if isinstance(keys, str):
            keys = [keys]
        self._virsh("send-key", self.name, *[str(k) for k in keys], check=False)

    def _media_scope(self) -> list[str]:
        return ["--live", "--config"] if self.is_running() else ["--config"]

    def insert_cd(self, iso_path: str, target: str = "hdc") -> None:
        # ppc/mac99 has NO managed <disk device='cdrom'> (the macio-IDE bus rides
        # entirely in <qemu:commandline>), so `change-media hdc` has no device to
        # act on and fails. There's no working IDE-CD hot-plug on the screamer
        # OpenBIOS build either, so we attach-at-boot: rewrite the persistent
        # definition to carry a `-drive ...,media=cdrom` for this ISO and reboot the
        # domain so OS 9 mounts the disc at startup. research/64.
        if self._is_ppc():
            self._ppc_set_cdrom(str(iso_path))
            return
        self._virsh(
            "change-media", self.name, target, str(iso_path), "--update", *self._media_scope()
        )

    def eject_cd(self, target: str = "hdc") -> None:
        if self._is_ppc():
            self._ppc_set_cdrom(None)
            return
        self._virsh("change-media", self.name, target, "--eject", *self._media_scope(), check=False)

    # The fixed qemu drive index for the datalink CD on a ppc domain. 0 = the
    # system disk, 2 = the (install-only) boot_iso; 3 keeps the datalink CD clear
    # of both so an installer ISO and a datalink CD can coexist.
    _PPC_CD_INDEX = "3"

    def _ppc_set_cdrom(self, iso_path: str | None) -> bool:
        """Attach (iso_path set) or detach (None) the datalink CD on a ppc/mac99
        domain by editing the persistent qemu:commandline and rebooting so the
        guest re-enumerates the macio-IDE bus. Returns True if a reboot was issued
        (i.e. the definition changed). Idempotent: a no-op (already-attached same
        ISO / already-absent) neither rewrites nor reboots."""
        ns = "http://libvirt.org/schemas/domain/qemu/1.0"
        ET.register_namespace("qemu", ns)
        try:
            root = ET.fromstring(self.dumpxml())
        except (BackendError, ET.ParseError) as e:
            raise BackendError(f"ppc CD attach: cannot read domain XML: {e}") from e
        cmdline = root.find(f"./{{{ns}}}commandline")
        if cmdline is None:
            raise BackendError("ppc CD attach: domain has no <qemu:commandline>")
        args = list(cmdline)  # [-drive, <val>, -drive, <val>, ...] flat arg/value list

        # The PROVEN-working CD form on this screamer/OpenBIOS mac99 build is the
        # SIMPLE `-drive ...,media=cdrom,index=N` (identical to the boot_iso path in
        # domain.xml.j2, which OS 9 mounts): qemu auto-attaches it to the onboard
        # macio-IDE bus where OS 9 finds CDs. The split `-drive if=none` + `-device
        # ide-cd` form is NOT used (it does not auto-place on macio).
        want = None
        if iso_path is not None:
            want = f"file={iso_path},format=raw,media=cdrom,index={self._PPC_CD_INDEX}"

        # Find the existing datalink CD drive arg (the -drive whose value carries our
        # fixed index + id) and the -drive flag that precedes it.
        cur_flag_i = None
        cur_val = None
        for i, el in enumerate(args):
            val = el.get("value") or ""
            if (
                el.tag == f"{{{ns}}}arg"
                and "media=cdrom" in val
                and (f"index={self._PPC_CD_INDEX}") in val
            ):
                # the preceding element is its -drive flag
                cur_flag_i = i - 1 if i > 0 else None
                cur_val = val
                break

        # No change needed?
        if want is not None and cur_val == want:
            return False
        if want is None and cur_val is None:
            return False

        # Drop the existing datalink CD drive (flag + value) if present.
        if cur_flag_i is not None:
            # remove value first (higher index), then its -drive flag
            cmdline.remove(args[cur_flag_i + 1])
            cmdline.remove(args[cur_flag_i])

        # Append the new drive if attaching.
        if want is not None:
            flag = ET.SubElement(cmdline, f"{{{ns}}}arg")
            flag.set("value", "-drive")
            value_el = ET.SubElement(cmdline, f"{{{ns}}}arg")
            value_el.set("value", want)

        xml = ET.tostring(root, encoding="unicode")
        self.define_xml(xml)
        # The persistent edit only takes effect on the next cold boot, and OS 9 must
        # re-enumerate the IDE bus to see the disc — so do a hard power-cycle.
        if self.is_running():
            self.stop()
            self.start()
        return True

    # --- guest agent ------------------------------------------------------
    def guest_ping(self, timeout: float = 5.0) -> bool:
        try:
            self._agent({"execute": "guest-ping"}, timeout=timeout)
            return True
        except (BackendError, subprocess.TimeoutExpired, json.JSONDecodeError):
            return False

    def guest_exec(
        self, path: str, args: list[str] | None = None, *, timeout: float = 15.0
    ) -> tuple[int, str, str]:
        ret = self._agent(
            {
                "execute": "guest-exec",
                "arguments": {"path": path, "arg": args or [], "capture-output": True},
            }
        )
        pid = ret["pid"]
        deadline = time.time() + timeout
        while time.time() < deadline:
            time.sleep(0.4)
            st = self._agent({"execute": "guest-exec-status", "arguments": {"pid": pid}})
            if st.get("exited"):
                out = base64.b64decode(st.get("out-data", "")).decode("utf-8", "replace")
                err = base64.b64decode(st.get("err-data", "")).decode("utf-8", "replace")
                return st.get("exitcode", -1), out, err
        return -1, "", "timeout"

    def guest_write_file(self, guest_path: str, data: bytes) -> None:
        handle = self._agent(
            {
                "execute": "guest-file-open",
                "arguments": {"path": guest_path, "mode": "wb"},
            }
        )
        try:
            for off in range(0, len(data), 36000):
                chunk = data[off : off + 36000]
                self._agent(
                    {
                        "execute": "guest-file-write",
                        "arguments": {
                            "handle": handle,
                            "buf-b64": base64.b64encode(chunk).decode(),
                        },
                    }
                )
        finally:
            self._agent({"execute": "guest-file-close", "arguments": {"handle": handle}})

    def guest_read_file(self, guest_path: str) -> bytes:
        handle = self._agent(
            {
                "execute": "guest-file-open",
                "arguments": {"path": guest_path, "mode": "rb"},
            }
        )
        data = b""
        try:
            while True:
                r = self._agent(
                    {
                        "execute": "guest-file-read",
                        "arguments": {"handle": handle, "count": 65536},
                    }
                )
                chunk = base64.b64decode(r.get("buf-b64", ""))
                data += chunk
                if r.get("eof") or not chunk:
                    break
        finally:
            self._agent({"execute": "guest-file-close", "arguments": {"handle": handle}})
        return data

    # --- network ----------------------------------------------------------
    def net_info(self) -> dict:
        subnet = self._discover_vm_network()
        info: dict = {"subnet": subnet, "interfaces": []}
        p = self._virsh("domifaddr", self.name, "--source", "agent", check=False)
        if p.returncode == 0:
            info["interfaces"] = [ln for ln in p.stdout.splitlines()[2:] if ln.strip()]
        return info

    def _discover_vm_network(self) -> str | None:
        try:
            p = self._virsh("domiflist", self.name, check=False)
            net = None
            for line in p.stdout.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "network":
                    net = parts[2]
                    break
            if not net:
                return None
            x = self._virsh("net-dumpxml", net, check=False)
            ip = ET.fromstring(x.stdout).find(".//ip")
            if ip is not None and ip.get("address") and ip.get("netmask"):
                return str(
                    ipaddress.IPv4Network(f"{ip.get('address')}/{ip.get('netmask')}", strict=False)
                )
        except Exception:
            return None
        return None

    def _flush_conntrack(self) -> None:
        """Clear stale TCP NAT entries after a revert/start. Best-effort."""
        subnet = self._discover_vm_network() or "192.168.122.0/24"
        with contextlib.suppress(FileNotFoundError, subprocess.SubprocessError):
            subprocess.run(
                ["conntrack", "-D", "-s", subnet],
                capture_output=True,
                text=True,
                timeout=5,
            )
