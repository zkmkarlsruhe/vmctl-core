"""Linked-clone a base image and render its libvirt domain XML.

A clone is a copy-on-write qcow2 overlay backed by the immutable base, plus a
domain definition derived from the base's hardware hints. Cloning is instant and
near-zero-disk; resetting an instance to pristine = delete + recreate the overlay.
"""

from __future__ import annotations

import getpass
import os
import subprocess
import uuid as _uuid
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from vmctl_core.atomicio import write_text_atomic
from vmctl_core.catalog import BaseImage
from vmctl_core.paths import safe_segment

_TEMPLATES = Path(__file__).parent / "templates"
_env = Environment(
    loader=FileSystemLoader(str(_TEMPLATES)),
    autoescape=select_autoescape(enabled_extensions=("xml", "j2")),
    keep_trailing_newline=True,
)

DEFAULT_EMULATOR = "/usr/bin/qemu-system-x86_64"


def random_mac() -> str:
    """A QEMU-range (52:54:00) locally-administered MAC."""
    tail = os.urandom(3)
    return f"52:54:00:{tail[0]:02x}:{tail[1]:02x}:{tail[2]:02x}"


# ppc/mac99 NIC is a RAW -netdev tap (research/58): a libvirt-managed <interface>
# lands the sungem on a PCI bus OS 9 can't bind, so the tap is host-managed instead.
# The host bridge the tap joins by DEFAULT (virbr0 is libvirt's "default" NAT network's
# bridge, whose dnsmasq leases the per-instance IP guest_ip() later parses). rvmc passes
# the instance's project bridge (rvmc-p<idx>0) instead under per-project net isolation.
# Either way the tap port is bridge-ISOLATED: two ppc clones of the same golden share a
# computer name, and Bonjour between them pops a "name already in use" modal over the
# artwork. An isolated port still reaches the host (dnsmasq, agent, poll, wbc gateway),
# just never another isolated port, i.e. another ppc clone on the same bridge.
PPC_TAP_BRIDGE = "virbr0"
# The qemu user that must own the tap (qemu.conf user). On the deploy box qemu runs
# as the deploying user (libvirt session/user-as-qemu, namespaces=[]); see deploy note.
# Default: the user running the controller, never one deployment's login.
PPC_TAP_USER = os.environ.get("RVMC_QEMU_USER") or getpass.getuser()
# Linux IFNAMSIZ caps an interface name at 15 chars (+NUL). "os9" + 8 hex of the
# domain/instance id = 11 chars, comfortably under the limit and per-instance unique.
_TAP_PREFIX = "os9"


def ppc_tap_name(domain_name: str) -> str:
    """Per-instance tap name for a ppc/mac99 domain. <=15 chars (Linux IFNAMSIZ):
    "os9" + the first 8 hex of a stable digest of the domain name. Deterministic so
    the same domain always maps to the same tap (idempotent create + clean delete)."""
    import hashlib

    h = hashlib.sha1(domain_name.encode("utf-8")).hexdigest()[:8]
    return f"{_TAP_PREFIX}{h}"


#: Short bound for the `sudo ip` tap plumbing — a hung sudo (auth prompt, stuck bridge) must not
#: block the clone forever, matching the timeouts the libvirt backend already sets on virsh.
_TAP_TIMEOUT_S = 30
#: Generous bound for `qemu-img create` (thin overlay is instant; a large blank disk is slower but
#: still bounded) — an I/O-wedged qemu-img otherwise hangs the caller indefinitely.
_QEMU_IMG_TIMEOUT_S = 300


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, timeout=_TAP_TIMEOUT_S)


def _tap_ready(tap: str, bridge: str) -> bool:
    """True only if `tap` EXISTS, is administratively UP, enslaved to `bridge`, and a
    bridge-isolated port. A merely-present tap (down, off the bridge, on the WRONG bridge,
    or not isolated) is NOT ready: the raw sungem NIC would open it but the guest would
    never reach the right dnsmasq / would see its sibling clones. Parses `ip -d -o link
    show` for the UP flag (inside the `<...>` flag list), `master <bridge>` and
    `isolated on` (bridge_slave detail)."""
    p = _run(["ip", "-d", "-o", "link", "show", tap])
    if p.returncode != 0:
        return False
    out = p.stdout
    flags = out.split("<", 1)[1].split(">", 1)[0] if "<" in out else ""
    is_up = "UP" in flags.split(",")
    enslaved = f"master {bridge} " in out + " "
    return is_up and enslaved and "isolated on" in out


def create_ppc_tap(tap: str, *, bridge: str = PPC_TAP_BRIDGE, user: str = PPC_TAP_USER) -> None:
    """Idempotently create a tap on `bridge`, owned by `user`, and bring it up.
    No-op if the tap already exists AND is UP + enslaved. Uses passwordless `sudo ip`.

    The raw qemu sungem NIC opens this pre-existing tap (script=no), so it MUST
    exist + be UP + on the NAT bridge before the domain starts, else qemu fails to open
    it / the guest never reaches dnsmasq. ppc-only; never called for x86 guests.

    On a partial failure (add ok, but up/enslave fails) the half-created tap is torn
    down before raising, so a retry starts clean instead of trusting a down/unbridged
    stub — a bare `ip link show`==0 (present) is NOT proof the tap is usable."""
    # Fully plumbed already (exists, UP, on the bridge)? idempotent no-op.
    if _tap_ready(tap, bridge):
        return
    # A stale/half-created tap (present but down or off the bridge, from a crashed
    # earlier attempt) must not be trusted — remove it and recreate clean.
    if _run(["ip", "link", "show", tap]).returncode == 0:
        _run(["sudo", "ip", "link", "del", tap])
    p = _run(["sudo", "ip", "tuntap", "add", "dev", tap, "mode", "tap", "user", user])
    if p.returncode != 0:
        raise CloneError(f"tap create failed for {tap}: {p.stderr.strip()}")
    up = _run(["sudo", "ip", "link", "set", tap, "up"])
    if up.returncode != 0:
        _run(["sudo", "ip", "link", "del", tap])  # don't leave a down half-tap behind
        raise CloneError(f"tap up failed for {tap}: {up.stderr.strip()}")
    enslave = _run(["sudo", "ip", "link", "set", tap, "master", bridge])
    if enslave.returncode != 0:
        _run(["sudo", "ip", "link", "del", tap])  # don't leave an unbridged half-tap behind
        raise CloneError(f"tap enslave to {bridge} failed for {tap}: {enslave.stderr.strip()}")
    iso = _run(["sudo", "ip", "link", "set", "dev", tap, "type", "bridge_slave", "isolated", "on"])
    if iso.returncode != 0:
        _run(["sudo", "ip", "link", "del", tap])  # never leave a non-isolated ppc port behind
        raise CloneError(f"tap isolate failed for {tap}: {iso.stderr.strip()}")
    # Confirm the tap actually came up UP+enslaved before trusting it (guards a silent
    # no-op success from a stubbed/odd `ip`).
    if not _tap_ready(tap, bridge):
        _run(["sudo", "ip", "link", "del", tap])
        raise CloneError(f"tap {tap} not UP+enslaved+isolated on {bridge} after setup")


def delete_ppc_tap(tap: str) -> None:
    """Remove a per-instance ppc tap (idempotent — best-effort, never raises).
    Called by the backend on undefine/destroy of a ppc domain."""
    if not tap:
        return
    _run(["sudo", "ip", "link", "del", tap])


class CloneError(RuntimeError):
    pass


def make_overlay(base_path: Path, overlay_path: Path) -> None:
    """Create a qcow2 overlay (CoW) backed by an immutable base. The base is
    read-only — never written. Pass -F so libvirt accepts the backing format."""
    base_path = Path(base_path)
    overlay_path = Path(overlay_path)
    if not base_path.is_file():
        raise CloneError(f"base image not found: {base_path}")
    overlay_path.parent.mkdir(parents=True, exist_ok=True)
    if overlay_path.exists():
        overlay_path.unlink()
    p = subprocess.run(
        [
            "qemu-img",
            "create",
            "-f",
            "qcow2",
            "-b",
            str(base_path),
            "-F",
            "qcow2",
            str(overlay_path),
        ],
        capture_output=True,
        text=True,
        timeout=_QEMU_IMG_TIMEOUT_S,
    )
    if p.returncode != 0:
        raise CloneError(f"qemu-img create failed: {p.stderr.strip()}")


def make_blank_disk(disk_path: Path, size_gb: int) -> None:
    """Create a fresh empty qcow2 (no backing file) of `size_gb` GiB. Used by
    install/provisioning bases that have no golden image yet — the guest installer
    partitions+formats this blank disk itself (e.g. Mac OS 9 Drive Setup -> APM/HFS+)."""
    disk_path = Path(disk_path)
    disk_path.parent.mkdir(parents=True, exist_ok=True)
    if disk_path.exists():
        disk_path.unlink()
    p = subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", str(disk_path), f"{int(size_gb)}G"],
        capture_output=True,
        text=True,
        timeout=_QEMU_IMG_TIMEOUT_S,
    )
    if p.returncode != 0:
        raise CloneError(f"qemu-img create (blank) failed: {p.stderr.strip()}")


def _resolve_catalog_path(p: str, catalog_dir: Path | None) -> str:
    """Resolve a catalog-relative path against the catalog dir — parity with
    BaseImage.resolved_path (main disk) and the aux_disks in clone_base, which BOTH
    resolve relative paths this way. An absolute path or empty string passes through;
    a None catalog_dir (bare render / preview) leaves the value untouched."""
    if not p or catalog_dir is None:
        return p
    pp = Path(p)
    return p if pp.is_absolute() else str((Path(catalog_dir) / pp).resolve())


def resolve_emulator(base: BaseImage, default: str = DEFAULT_EMULATOR) -> str:
    """Per-base QEMU binary if the catalog pins one (e.g. the ppc/mac99 screamer
    fork), else the deployment x86 default. Keeps existing x86 bases unchanged."""
    return base.hw.emulator or default


# research/56: the agent channel is a POOL of independent single-client vioser lanes.
#   .0  control  — status/polls (cheap, must stay responsive)
#   .1  drive    — keys/pointer/screenshot (fast, high-rate)
#   .2..N-1      — worker pool: heavy/slow calls (eventlog/log/file/shell/exec/
#                  installer + unknown) dispatched round-robin across these by the host.
# Lane .0 keeps the legacy bare `<domain>.sock` (back-compat with single-channel
# goldens); lanes 1+ get `<domain>.<lane>.sock`. Must match
# rvmc.guest_bridge.lane_sock_path so the host connects to the right per-lane socket.
#
# Configurable via the AGENT_LANES env var (default 1). AGENT_LANES=1 reproduces the
# old single-channel XML byte-for-byte (lane .0 only).
#
# DEFAULT capped at 1 (lane .0 only): emitting >2 virtio-serial
# ports WEDGES the modern virtio-win driver (win11/win10) — the guest serving 3+ ports
# concurrently stalls a read_file reply on any lane, so portal PULL timed out there
# (verified 2026-07-18: win11 pull fails at 8 ports, byte-identical at 1; still timed out at 2). Must stay
# in sync with rvmc.guest_bridge.DEFAULT_AGENT_LANES.
DEFAULT_AGENT_LANES = 1

# Usable ports per virtio-serial controller. QEMU's default vioser controller offers
# 32 ports, port 0 is reserved for the console => 31 usable. If the channel count
# (qemu-ga + agent lanes) exceeds one controller, the template emits a second.
VIOSER_MAX_PORTS = 31


def _agent_lanes() -> int:
    """Configured lane-pool size (env AGENT_LANES, default 8, floored at 1)."""
    try:
        return max(1, int(os.environ.get("AGENT_LANES", DEFAULT_AGENT_LANES)))
    except (TypeError, ValueError):
        return DEFAULT_AGENT_LANES


# Back-compat alias: callers / tests that imported the old constant still resolve a
# concrete int (the configured pool size at import time).
AGENT_LANES = _agent_lanes()


def agent_lane_socks(agent_sock: str, lanes: int | None = None) -> list[str]:
    """Per-lane bind paths derived from the base lane-.0 socket. `<domain>.sock` for
    lane 0; `<domain>.<lane>.sock` for lanes 1+. Empty list if no agent channel.
    `lanes` defaults to the configured pool size (env AGENT_LANES, default 8)."""
    if not agent_sock:
        return []
    if lanes is None:
        lanes = _agent_lanes()
    base = Path(agent_sock)
    out = [str(base)]
    for lane in range(1, lanes):
        out.append(
            str(
                base.with_suffix(f".{lane}.sock")
                if base.suffix == ".sock"
                else Path(str(base) + f".{lane}.sock")
            )
        )
    return out


def render_domain_xml(
    base: BaseImage,
    *,
    name: str,
    disk_path: Path,
    title: str = "",
    network: str = "default",
    emulator: str = DEFAULT_EMULATOR,
    mac: str | None = None,
    domain_uuid: str | None = None,
    agent_sock: str = "",
    pulse_server: str = "",
    aux_disk_paths: list[str] | None = None,
    catalog_dir: Path | None = None,
) -> str:
    # A base may pin its own emulator (ppc screamer fork); it wins over the
    # deployment x86 default passed in. x86 bases leave hw.emulator unset => default.
    emulator = resolve_emulator(base, emulator)
    # boot_iso (ppc install CD) and loader (macOS OVMF firmware) resolve relative to the
    # catalog dir, exactly like the main disk (resolved_path) and aux_disks — a catalog
    # that ships these as relative paths must render to absolutes qemu/libvirt can open.
    boot_iso = _resolve_catalog_path(base.hw.boot_iso or "", catalog_dir)
    loader = _resolve_catalog_path(base.hw.loader or "", catalog_dir)
    # macOS aux disks (OpenCore) are read-only bases with per-clone writable overlays,
    # like the main disk. clone_base passes the created overlay paths; a bare render (no
    # overlays) falls back to the shared base paths so preview/tests still show the disks.
    _aux_srcs = (
        aux_disk_paths if aux_disk_paths is not None else [a.path for a in base.hw.aux_disks]
    )
    aux_disks_resolved = [
        {"path": src, "bus": a.bus, "boot": a.boot}
        for a, src in zip(base.hw.aux_disks, _aux_srcs, strict=True)
    ]
    return _env.get_template("domain.xml.j2").render(
        name=name,
        uuid=domain_uuid or str(_uuid.uuid4()),
        title=title or name,
        hw=base.hw,
        disk_path=str(disk_path),
        aux_disks_resolved=aux_disks_resolved,
        network=network,
        emulator=emulator,
        mac=mac or random_mac(),
        # Per-instance host-managed tap for the ppc/mac99 raw sungem NIC. Only the
        # ppc branch of the template consumes it; x86 branches ignore it entirely.
        tap=ppc_tap_name(name) if base.hw.arch == "ppc" else "",
        agent_sock=agent_sock,
        # Multi-lane pool (research/56): emit N agent channels (env AGENT_LANES,
        # default 8). Lane .0 == agent_sock so old single-channel goldens are
        # byte-for-byte unaffected when AGENT_LANES drops to 1.
        agent_socks=agent_lane_socks(agent_sock),
        # A single virtio-serial controller exposes 31 usable ports (port 0 reserved
        # for the console). With the qemu guest-agent channel + N agent lanes a large
        # pool could exceed that, so tell the template how many controllers to emit.
        vioser_max_ports=VIOSER_MAX_PORTS,
        pulse_server=pulse_server,
        # Catalog-resolved (relative -> absolute) boot ISO + firmware paths; the
        # template consumes these instead of hw.boot_iso / hw.loader directly.
        boot_iso=boot_iso,
        loader=loader,
    )


def clone_base(
    base: BaseImage,
    *,
    catalog_dir: Path,
    domain_name: str,
    overlays_dir: Path,
    xml_dir: Path,
    network: str = "default",
    emulator: str = DEFAULT_EMULATOR,
    agent_sock: str = "",
    pulse_server: str = "",
    ppc_bridge: str = PPC_TAP_BRIDGE,
) -> tuple[Path, Path]:
    """Make the overlay + write the domain XML. Returns (overlay_path, xml_path).
    Does NOT define/start — the caller drives the backend."""
    # domain_name is interpolated into overlay/XML paths below; containment must not
    # depend on the caller having slug-validated it (rvmc's REST edge does, other
    # consumers of this library may not).
    safe_segment(domain_name, field="domain_name")
    # ppc/mac99 NIC is a raw host-managed tap (not a libvirt-managed interface): it
    # MUST exist on the NAT bridge, owned by the qemu user, before the domain is
    # defined+started. Create it here (idempotent). x86 guests skip this entirely —
    # libvirt creates+owns their tap automatically. (research/58)
    if base.hw.arch == "ppc":
        create_ppc_tap(ppc_tap_name(domain_name), bridge=ppc_bridge)

    overlay_path = Path(overlays_dir) / f"{domain_name}.qcow2"
    if base.hw.blank_disk_gb > 0:
        # No golden base yet (install/provision VM): the guest installer formats a
        # fresh empty disk itself. Skip the CoW overlay.
        make_blank_disk(overlay_path, base.hw.blank_disk_gb)
    else:
        base_path = base.resolved_path(Path(catalog_dir))
        make_overlay(base_path, overlay_path)

    # macOS aux disks (OpenCore): each is a shared read-only base that gets its own
    # per-clone writable overlay (qemu has no readonly IDE/SATA disk; a shared writable
    # one would corrupt). OpenCore writes its NVRAM to the overlay. Non-macOS bases have
    # no aux_disks, so this loop is a no-op for them.
    aux_overlays: list[str] = []
    for i, aux in enumerate(base.hw.aux_disks):
        aux_base = Path(aux.path)
        if not aux_base.is_absolute():
            aux_base = (Path(catalog_dir) / aux_base).resolve()
        aux_overlay = Path(overlays_dir) / f"{domain_name}-aux{i}.qcow2"
        make_overlay(aux_base, aux_overlay)
        aux_overlays.append(str(aux_overlay))

    xml = render_domain_xml(
        base,
        name=domain_name,
        disk_path=overlay_path,
        title=domain_name,
        network=network,
        emulator=emulator,
        agent_sock=agent_sock,
        pulse_server=pulse_server,
        aux_disk_paths=aux_overlays,
        catalog_dir=Path(catalog_dir),
    )
    Path(xml_dir).mkdir(parents=True, exist_ok=True)
    xml_path = Path(xml_dir) / f"{domain_name}.xml"
    # Atomic: libvirt reads this domain XML on define; a torn write (crash mid-clone) must not
    # leave a half-written XML that define() then rejects.
    write_text_atomic(xml_path, xml)
    return overlay_path, xml_path
