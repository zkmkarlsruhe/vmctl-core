# Mac OS 9 (ppc/mac99) networking: raw tap NIC

## What changed

The ppc/mac99 (Mac OS 9) sungem NIC was reconciled from a **discredited** libvirt-managed
`<interface model='sungem'>` to the **proven** raw `<qemu:commandline>` tap NIC.

### Why the managed interface is wrong
libvirt always lands a managed `<interface>` on a PCI bus (AGP / `pci.0`). On mac99, OS 9's
Open Transport cannot bind the sungem there, so the NIC never appears in the guest and it never
sends a DHCP request — no lease, no IP.

### The proven form (validated 2026-06-22 on rvmc-ck1/2/3 + the golden, and re-verified here)
A raw cmdline NIC with **no bus/addr** — qemu then auto-places `sungem` on `pci.2` (the
uni-north main bus where macio lives), exactly where OS 9 binds "Ethernet (built-in)":

```
-netdev tap,id=net0,ifname=<per-instance-tap>,script=no,downscript=no
-device sungem,netdev=net0,mac=<mac>
```

The tap must pre-exist on `virbr0`, owned by the qemu user, before the domain starts.

## Implementation

- **`vmctl_core/templates/domain.xml.j2`** (ppc branch): removed the managed `<interface>`;
  emits the raw `-netdev tap` + `-device sungem` (no bus) in `<qemu:commandline>`. The x86
  branch is byte-for-byte unchanged (`tap=""` is rendered only by the ppc branch).
- **`vmctl_core/clone.py`**: `ppc_tap_name(domain)` derives the tap (`"os9" + sha1(domain)[:8]`,
  11 chars, under Linux IFNAMSIZ=15). `create_ppc_tap()` idempotently creates it on `virbr0`
  owned by the qemu user via passwordless `sudo ip`, before define/start. `clone_base()` calls
  it only when `base.hw.arch == "ppc"`. `delete_ppc_tap()` removes it.
- **`vmctl_core/backends/libvirt_backend.py`**:
  - `undefine()` reads the tap from the domain XML's `-netdev ...,ifname=` arg **before**
    undefine, then calls `delete_ppc_tap()` after. x86 domains have no such NIC (no-op).
  - `guest_ip()`: for ppc (cmdline NIC, which `virsh domifaddr` is blind to) falls back to
    parsing `/var/lib/libvirt/dnsmasq/virbr0.status` by the domain's MAC (read from the
    `-device sungem,...,mac=` arg). x86 path (domifaddr lease/arp/agent) unchanged.

All changes are **ppc-guarded**; winxp/win10/debian x86 guests are unaffected.

## Tap-name scheme

`"os9" + first 8 hex of sha1(domain_name)` — deterministic (same domain ⇒ same tap, so create
is idempotent and delete is exact) and 11 chars (≤ IFNAMSIZ-1).

## Test result (live, on the lab host)

Cloned `mac9` (golden `mac9-922-agent-golden.qcow2`, `agent:true`) into project `verify`:

- Instance `rvmc-verify-5ca3a0` defined + started.
- Tap `os9645b349c` appeared on virbr0 (UP, LOWER_UP — qemu opened it).
- Domain XML had the raw sungem cmdline NIC and **zero** managed `<interface>` elements.
- Guest pulled DHCP lease `192.168.122.191` (~60 s).
- `LibvirtBackend.guest_ip()` resolved `192.168.122.191` via the dnsmasq fallback
  (`_domain_arch()`→ppc, `_domain_macs()`→sungem mac, `_ppc_tap()`→os9645b349c).
- Bonus: both faceless agents answered — `:9610` (`{"ok":true,"mode":"full","python":"2.3.3"}`)
  and `:9611` recovery channel.
- Destroy removed the domain + overlay, and the tap `os9645b349c` was gone.
- The pre-existing running domain `rvmc-macos-6c528f` was untouched throughout.

**PASS.**

## Host-config caveats

- qemu runs as the deploying user; the tap is created `user <that user>`. The qemu user
  is overridable via `RVMC_QEMU_USER` (default: the user running the controller).
- Requires passwordless `sudo ip` on the host (present on the box).
- Requires the host-side libvirt qemu.conf already having `namespaces=[]` + `/dev/net/tun` in
  `cgroup_device_acl` so qemu (as a non-root user, no namespacing) can open the pre-made tap.
- `guest_ip()` reads `/var/lib/libvirt/dnsmasq/virbr0.status` (world-readable). Bridge name is
  hardcoded `virbr0` (libvirt's "default" NAT network) — matches `PPC_TAP_BRIDGE` in clone.py.
- The rvmc service must set `RVMC_STATE_DIR` to an **absolute** path so the overlay disk path in
  the domain XML is absolute (qemu's cwd differs); the systemd `rvmc` unit already does this.
