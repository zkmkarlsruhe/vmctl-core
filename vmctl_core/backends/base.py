"""The VMBackend contract.

The controller talks only to this Protocol, so the same project/instance/snapshot
logic runs against different substrates:

* ``LibvirtBackend`` (qemu:///system) — the local-dev + bare-metal target (now).
* a ``qemu-direct`` (QMP) backend — self-contained QEMU in a container (later).

A backend instance is bound to ONE domain/instance (identified by ``name``). It is
deliberately low-level: lifecycle, snapshots, framebuffer, guest agent, VNC
endpoint, and domain (un)definition. Catalog, cloning, projects, and the registry
live one layer up and are backend-agnostic.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


class BackendError(RuntimeError):
    """A backend operation failed (wraps the underlying tool's stderr)."""


@runtime_checkable
class VMBackend(Protocol):
    """Everything the controller needs from a single VM instance."""

    name: str  # the domain / instance identifier in the backend

    # --- existence & state ------------------------------------------------
    def exists(self) -> bool: ...
    def state(self) -> str: ...
    def is_running(self) -> bool: ...

    # --- lifecycle --------------------------------------------------------
    def start(self) -> None:
        """Power on the (already-defined) domain. Does NOT revert a snapshot."""

    def stop(self) -> None:
        """Hard power-off (equivalent to pulling the cord). Idempotent."""

    def shutdown(self) -> None:
        """Request a graceful ACPI shutdown (best-effort)."""

    def reboot(self) -> None:
        """Graceful in-guest reboot (ACPI / guest agent)."""

    def reset(self) -> None:
        """Hard reset — power-cycle without a clean shutdown."""

    # --- settings ---------------------------------------------------------
    def get_settings(self) -> dict:
        """Current tunables: {memory_mb, vcpus, autostart, state, persistent}."""

    def set_settings(
        self,
        *,
        memory_mb: int | None = None,
        vcpus: int | None = None,
        autostart: bool | None = None,
    ) -> None:
        """Update persistent domain tunables. memory/vcpu changes take effect on
        next boot; autostart is immediate."""

    def tap_interface(self) -> str | None:
        """Host-side tap device (vnetN) for this domain, for packet capture."""

    # --- domain definition ------------------------------------------------
    def define(self, xml_path: str) -> None:
        """Define/redefine the persistent domain from an XML file."""

    def undefine(self) -> None:
        """Remove the persistent domain definition (not the disk)."""

    # --- snapshots (internal disk+RAM by default) -------------------------
    def snapshot_list(self) -> list[str]: ...

    def snapshot_create(self, name: str, *, memory: bool = True) -> None:
        """Create/overwrite a snapshot. memory=True captures the live RAM state
        so a revert returns to the exact running moment."""

    def snapshot_revert(self, name: str) -> None: ...
    def snapshot_delete(self, name: str) -> None: ...

    # --- screen -----------------------------------------------------------
    def screenshot(self, screen: int = 0) -> bytes:
        """PNG bytes of a display head, captured with no guest cooperation."""

    def vnc_endpoint(self) -> tuple[str, int] | None:
        """(host, port) of the domain's VNC server, or None if not graphical."""

    def send_key(self, keys: list[str]) -> None:
        """Inject keystrokes at the hypervisor (KEY_* names), e.g. ['KEY_ESC'] or
        ['KEY_LEFTCTRL','KEY_LEFTALT','KEY_DELETE']. Works with no guest agent."""

    def insert_cd(self, iso_path: str) -> None:
        """Load an ISO into the guest's CD-ROM (universal read-only share — works
        on legacy guests with no drivers; e.g. the virtio-win driver disc)."""

    def eject_cd(self) -> None:
        """Eject the CD-ROM."""

    # --- guest agent (optional per guest; raises if unavailable) ----------
    def guest_ping(self, timeout: float = 5.0) -> bool: ...

    def guest_exec(
        self, path: str, args: list[str] | None = None, *, timeout: float = 15.0
    ) -> tuple[int, str, str]:
        """Run a program in the guest via the QEMU guest agent → (rc, out, err)."""

    def guest_write_file(self, guest_path: str, data: bytes) -> None: ...
    def guest_read_file(self, guest_path: str) -> bytes: ...

    # --- network ----------------------------------------------------------
    def net_info(self) -> dict:
        """Best-effort: discovered subnet + guest interface addresses."""
