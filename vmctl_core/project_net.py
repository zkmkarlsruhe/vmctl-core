"""Per-project isolated libvirt networks (network-isolation hardening).

Each project gets its OWN isolated libvirt network so guests in different projects can
never reach one another: separate bridge, separate /24, separate gateway + dnsmasq, and
crucially NO ``<forward>`` element — libvirt then installs FORWARD rules that REJECT any
traffic leaving the bridge (same containment shape as ``deploy/networks/rvmc-mgmt.xml``).
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
tailnet advertises ``10.0.0.0/24`` / ``10.1.0.0/24`` and many ``192.168.x/24`` routes;
rvmc-mgmt is ``10.77.0.0/24`` (distinct from ``10.177``). ``10.177/16`` collides with none
and leaves the rest of ``10/8`` free.
"""

from __future__ import annotations

import contextlib
import ipaddress
import os
import subprocess
import tempfile
from dataclasses import dataclass

from .backends.base import BackendError

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


def render_network_xml(pn: ProjectNet) -> str:
    """The ISOLATED libvirt ``<network>`` XML for a project net — bridge + DHCP, and
    deliberately NO ``<forward>`` (the containment: libvirt REJECTs traffic off the
    bridge, so the guest reaches only its gateway, never another project or the LAN).
    Mirrors ``deploy/networks/rvmc-mgmt.xml``."""
    return (
        f"<!-- rvmc per-project isolated net (index {pn.index}). NO <forward>: "
        f"containment. Generated — do not hand-edit. -->\n"
        f"<network>\n"
        f"  <name>{pn.name}</name>\n"
        f"  <bridge name='{pn.bridge}' stp='on' delay='0'/>\n"
        f"  <ip address='{pn.gateway}' netmask='{pn.netmask}'>\n"
        f"    <dhcp>\n"
        f"      <range start='{pn.dhcp_start}' end='{pn.dhcp_end}'/>\n"
        f"    </dhcp>\n"
        f"  </ip>\n"
        f"</network>\n"
    )


class LibvirtNetworks:
    """Thin ``virsh net-*`` wrapper (hosting-neutral). No sudo when the user is in the
    ``libvirt`` group and the URI is ``qemu:///system`` — same contract as
    :class:`~vmctl_core.backends.libvirt_backend.LibvirtBackend`."""

    def __init__(self, uri: str = "qemu:///system") -> None:
        self.uri = uri

    def _virsh(
        self, *args: str, timeout: float = 30.0, check: bool = True
    ) -> subprocess.CompletedProcess:
        cmd = ["virsh", "-c", self.uri, *args]
        env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        if check and p.returncode != 0:
            raise BackendError(f"virsh {' '.join(args)} failed: {p.stderr.strip()}")
        return p

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

    def ensure(self, pn: ProjectNet) -> None:
        """Define + autostart + start the project net, idempotently. Safe to call on
        every spawn: an already-defined/active net is a no-op. Does NOT touch VMs."""
        if not self.exists(pn.name):
            with tempfile.NamedTemporaryFile(
                "w", suffix=".xml", prefix=f"{pn.name}-", delete=False
            ) as f:
                f.write(render_network_xml(pn))
                xml_path = f.name
            try:
                self._virsh("net-define", xml_path)
            finally:
                with contextlib.suppress(OSError):
                    os.unlink(xml_path)
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

    def teardown(self, name: str) -> None:
        """Destroy (stop) + undefine a project net. Best-effort + idempotent — a missing
        or already-stopped net is fine. Call only once no guest is attached."""
        if not self.exists(name):
            return
        self._virsh("net-destroy", name, check=False)
        self._virsh("net-undefine", name, check=False)
