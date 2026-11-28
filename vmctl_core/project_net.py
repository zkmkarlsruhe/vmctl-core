"""Per-project isolated libvirt networks (network-isolation hardening).

Each project gets its OWN isolated libvirt network so guests in different projects can
never reach one another: separate bridge, separate /24, separate gateway + dnsmasq, and
crucially NO ``<forward>`` element — libvirt then installs FORWARD rules that REJECT any
traffic leaving the bridge.
Inter-project isolation is therefore inherent in the topology, not a firewall bolt-on.

This module is the hosting-neutral half (rvmc hosts it in-process today; evmctl reuses it
later): the deterministic index→network derivation, the isolated ``<network>`` XML render,
and a thin ``virsh net-*`` wrapper. The persistent ``pid → index`` registry + create/teardown
lifecycle live in the controller (it owns the state dir); this layer stays pure + reusable.

Addressing -- the ``10.177.0.0/16`` block, one ``/24`` per index (0-255):
  net name  ``rvmc-p<idx>``       gateway  ``10.177.<idx>.1``
  bridge    ``rvmc-p<idx>0``      dhcp     ``10.177.<idx>.2`` .. ``.254``
The block was chosen against every route reachable on the rvmc host so a guest bridge can
never shadow a real route: docker owns ``172.16/12``; tailscale CGNAT is ``100.64/10``; the
tailnet advertises ``10.0.0.0/24`` / ``10.1.0.0/24`` and many ``192.168.x/24`` routes.
``10.177/16`` collides with none
and leaves the rest of ``10/8`` free.
"""

from __future__ import annotations

import contextlib
import fcntl
import ipaddress
import os
import subprocess
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from dataclasses import dataclass

from vmctl_core.backends.base import BackendError
from vmctl_core.backends.libvirt_backend import virsh

#: second + third octet base — guest project nets live in 10.177.<idx>.0/24
NET_SECOND_OCTET = 177
#: usable index range (256 concurrent project nets in the 10.177/16 block)
MAX_INDEX = 255


@dataclass(frozen=True)
class ProjectNet:
    """A project's isolated libvirt network, derived from its allocated index.

    Pure value object: every field is a function of ``index`` alone, so the same index
    always yields the same network (stable across restarts, like ``wbc.host_port``)."""

    index: int
    name: str
    bridge: str
    subnet: str  # CIDR, e.g. "10.177.3.0/24"
    gateway: str  # e.g. "10.177.3.1"
    netmask: str  # e.g. "255.255.255.0"
    dhcp_start: str
    dhcp_end: str

    @classmethod
    def from_index(cls, index: int) -> ProjectNet:
        if not 0 <= index <= MAX_INDEX:
            raise ValueError(f"project-net index {index} out of range 0..{MAX_INDEX}")
        third = index
        net = ipaddress.IPv4Network(f"10.{NET_SECOND_OCTET}.{third}.0/24")
        hosts = net.network_address
        return cls(
            index=index,
            name=f"rvmc-p{index}",
            bridge=f"rvmc-p{index}0",
            subnet=str(net),
            gateway=str(hosts + 1),
            netmask=str(net.netmask),
            dhcp_start=str(hosts + 2),
            dhcp_end=str(hosts + 254),
        )

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.IPv4Network(self.subnet)

    def contains(self, ip: str) -> bool:
        """True if ``ip`` is an address on this project's subnet (used to resolve a
        connection's destination-gateway back to its project)."""
        try:
            return ipaddress.ip_address(ip) in self.network
        except ValueError:
            return False


#: libvirt's dnsmasq passthrough namespace (``<dnsmasq:options>``)
DNSMASQ_NS = "http://libvirt.org/schemas/network/dnsmasq/1.0"


def render_network_xml(pn: ProjectNet) -> str:
    """The ISOLATED libvirt ``<network>`` XML for a project net — bridge + DHCP, and
    deliberately NO ``<forward>`` (the containment: libvirt REJECTs traffic off the
    bridge, so the guest reaches only its gateway, never another project or the LAN).

    For an isolated net libvirt writes an EMPTY ``dhcp-option=3`` (no router), so guests
    get no default route and off-subnet traffic never reaches the host. The dnsmasq
    passthrough re-adds the gateway as router (it comes after libvirt's line in the conf):
    off-subnet packets then land on the host, where PREROUTING DNAT can take them; FORWARD
    still REJECTs everything else, so real internet stays blocked."""
    return (
        f"<!-- rvmc per-project isolated net (index {pn.index}). NO <forward>: "
        f"containment. Generated — do not hand-edit. -->\n"
        f"<network xmlns:dnsmasq='{DNSMASQ_NS}'>\n"
        f"  <name>{pn.name}</name>\n"
        f"  <bridge name='{pn.bridge}' stp='on' delay='0'/>\n"
        f"  <ip address='{pn.gateway}' netmask='{pn.netmask}'>\n"
        f"    <dhcp>\n"
        f"      <range start='{pn.dhcp_start}' end='{pn.dhcp_end}'/>\n"
        f"    </dhcp>\n"
        f"  </ip>\n"
        f"  <dnsmasq:options>\n"
        f"    <dnsmasq:option value='dhcp-option=3,{pn.gateway}'/>\n"
        f"  </dnsmasq:options>\n"
        f"</network>\n"
    )


def _net_signature(xml: str) -> tuple:
    """The fields of a network XML that rvmc owns, normalised so a ``net-dumpxml`` (which
    adds uuid, mac, defaults) compares equal to :func:`render_network_xml` when nothing
    relevant differs."""
    root = ET.fromstring(xml)
    ip = root.find("ip")
    rng = ip.find("dhcp/range") if ip is not None else None
    bridge = root.find("bridge")
    return (
        root.findtext("name"),
        root.find("forward") is not None,
        None if bridge is None else bridge.get("name"),
        None if ip is None else (ip.get("address"), ip.get("netmask")),
        None if rng is None else (rng.get("start"), rng.get("end")),
        tuple(o.get("value") for o in root.iter(f"{{{DNSMASQ_NS}}}option")),
    )


# ensure() is check-then-define; parallel spawns in one project raced it and libvirt
# logged "network 'rvmc-pN' already exists". flock per net name: locks bind to the open
# file description, so it serialises threads (each opens its own fd) AND processes
# (rvmc serve vs the rvmc CLI).
# shortcut: lock dir is per user ($XDG_RUNTIME_DIR), so callers under different users
# don't exclude each other; move to a shared dir if rvmc ever runs as several users.
@contextlib.contextmanager
def _ensure_lock(name: str) -> Iterator[None]:
    lock_dir = os.environ.get("XDG_RUNTIME_DIR") or tempfile.gettempdir()
    with open(os.path.join(lock_dir, f"vmctl-net-{name}.lock"), "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        yield


class LibvirtNetworks:
    """Thin ``virsh net-*`` wrapper (hosting-neutral). No sudo when the user is in the
    ``libvirt`` group and the URI is ``qemu:///system`` — same contract as
    :class:`~vmctl_core.backends.libvirt_backend.LibvirtBackend`."""

    def __init__(self, uri: str = "qemu:///system") -> None:
        self.uri = uri

    def _virsh(
        self, *args: str, timeout: float = 30.0, check: bool = True
    ) -> subprocess.CompletedProcess:
        return virsh(self.uri, *args, timeout=timeout, check=check)

    def exists(self, name: str) -> bool:
        return self._virsh("net-info", name, check=False).returncode == 0

    def is_active(self, name: str) -> bool:
        p = self._virsh("net-info", name, check=False)
        if p.returncode != 0:
            return False
        for line in p.stdout.splitlines():
            k, _, v = line.partition(":")
            if k.strip() == "Active":
                return v.strip() == "yes"
        return False

    def list_names(self) -> list[str]:
        """Every defined network (active or not)."""
        p = self._virsh("net-list", "--all", "--name", check=False)
        return [n for n in p.stdout.split() if n]

    def _define(self, xml: str, name: str) -> None:
        with tempfile.NamedTemporaryFile("w", suffix=".xml", prefix=f"{name}-", delete=False) as f:
            f.write(xml)
            xml_path = f.name
        try:
            self._virsh("net-define", xml_path)
        finally:
            with contextlib.suppress(OSError):
                os.unlink(xml_path)

    def ensure(self, pn: ProjectNet) -> None:
        """Define + autostart + start the project net, idempotently. Safe to call on
        every spawn: an already-defined/active net is a no-op. Does NOT touch VMs."""
        with _ensure_lock(pn.name):
            self._ensure(pn)

    def _ensure(self, pn: ProjectNet) -> None:
        if not self.exists(pn.name):
            self._define(render_network_xml(pn), pn.name)
        # autostart + start are individually idempotent (already-active start is an error
        # we swallow; net-autostart is a config flag).
        self._virsh("net-autostart", pn.name, check=False)
        if not self.is_active(pn.name):
            p = self._virsh("net-start", pn.name, check=False)
            # net-start is check=False (an already-active start is a benign error we
            # swallow), but a GENUINE start failure would otherwise return success while
            # the net stays down — every guest that then attaches gets no DHCP/routing.
            # Re-check and fail loudly if the net didn't actually come up.
            if not self.is_active(pn.name):
                raise BackendError(
                    f"project net {pn.name!r} failed to start: "
                    f"{p.stderr.strip() or 'still inactive after net-start'}"
                )

    def redefine(self, pn: ProjectNet) -> bool:
        """Bring an EXISTING project net in line with :func:`render_network_xml`.
        Idempotent: returns False (no-op) when the live XML already matches. Otherwise
        net-define (keeping uuid, mac and ``<dns>`` records), net-destroy, net-start and
        returns True. A restart drops the bridge: attached guests lose their NIC link and
        must be power-cycled by the caller. A missing net is left to :meth:`ensure`."""
        if not self.exists(pn.name):
            return False
        current = self._virsh("net-dumpxml", pn.name).stdout
        want = render_network_xml(pn)
        if _net_signature(current) == _net_signature(want):
            return False
        # keep what libvirt/rvmc added at runtime: uuid (same uuid = libvirt updates the
        # definition, autostart stays), bridge mac, and <dns> host records (vmctl.local)
        cur, new = ET.fromstring(current), ET.fromstring(want)
        for pos, tag in enumerate(("uuid", "mac", "dns"), start=1):
            el = cur.find(tag)
            if el is not None and new.find(tag) is None:
                new.insert(pos, el)
        ET.register_namespace("dnsmasq", DNSMASQ_NS)
        want = ET.tostring(new, encoding="unicode")
        self._define(want, pn.name)
        self._virsh("net-destroy", pn.name, check=False)
        self._virsh("net-start", pn.name)
        return True

    def teardown(self, name: str) -> None:
        """Destroy (stop) + undefine a project net. Best-effort + idempotent — a missing
        or already-stopped net is fine. Call only once no guest is attached."""
        if not self.exists(name):
            return
        self._virsh("net-destroy", name, check=False)
        self._virsh("net-undefine", name, check=False)
