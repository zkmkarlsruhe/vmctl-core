"""Libvirt domain definitions and virsh execution."""

from __future__ import annotations

import contextlib
import os
import subprocess
import xml.etree.ElementTree as ET
from collections.abc import Callable

from vmctl_core.backends.base import BackendError


def virsh(
    uri: str, *args: str, timeout: float = 30.0, check: bool = True
) -> subprocess.CompletedProcess:
    """The one ``virsh`` wrapper (domains here, networks in ``project_net``)."""
    return _invoke_virsh(uri, args, timeout, check, None)


_Runner = Callable[[list[str], float, bool], subprocess.CompletedProcess[str]]


def _invoke_virsh(
    uri: str, args: tuple[str, ...], timeout: float, check: bool, runner: _Runner | None
) -> subprocess.CompletedProcess[str]:
    cmd = ["virsh", "-c", uri, *args]
    try:
        if runner is None:
            # Force the C locale: stop()/get_settings() and the state parsers key off
            # English virsh output ("not running", "Max memory", "Autostart"); under a
            # localized LANG those substring checks silently break (stop() would raise on
            # an already-stopped domain; get_settings() would return defaults).
            env = {**os.environ, "LC_ALL": "C", "LANG": "C"}
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        else:
            p = runner(cmd, timeout, check)
        if check:
            p.check_returncode()
    except subprocess.CalledProcessError as e:
        raise BackendError(f"virsh {' '.join(args)} failed: {(e.stderr or '').strip()}") from e
    except subprocess.TimeoutExpired as e:
        # A hung libvirtd must surface as BackendError: state()/exists()/guest_ip()
        # catch only that and would otherwise leak a traceback.
        raise BackendError(f"virsh {' '.join(args)} timed out after {timeout:g}s") from e
    return p


class _LibvirtDomain:
    """Command execution and persistent definition for one libvirt domain."""

    def __init__(
        self, name: str, uri: str = "qemu:///system", *, runner: _Runner | None = None
    ) -> None:
        self.name = name
        self.uri = uri
        self._runner = runner

    # --- virsh plumbing ---------------------------------------------------
    def _virsh(
        self, *args: str, timeout: float = 30.0, check: bool = True
    ) -> subprocess.CompletedProcess:
        return _invoke_virsh(self.uri, args, timeout, check, self._runner)

    # --- domain definition ------------------------------------------------
    def define(self, xml_path: str) -> None:
        self._virsh("define", xml_path)

    def dumpxml(self) -> str:
        """The live/persistent domain XML."""
        return self._virsh("dumpxml", self.name).stdout

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

    def undefine(self, *, snapshots_metadata: bool = True, nvram: bool = False) -> None:
        # Capture the ppc tap BEFORE the definition is gone, then clean it up after
        # undefine. x86 domains have no host-managed tap here => _ppc_tap() is None.
        tap = self._ppc_tap()
        # --snapshots-metadata so internal snapshots don't block the undefine
        args = ["undefine", self.name]
        if snapshots_metadata:
            args.append("--snapshots-metadata")
        if nvram:
            args.append("--nvram")
        p = self._virsh(*args, check=False)
        # Tear the host tap down ONLY if the domain is actually gone. A failed undefine
        # (domain still defined — e.g. running, or a virsh error) must keep its NIC:
        # ripping the tap out from under a still-defined/running ppc guest kills its
        # networking with no way back short of a re-clone.
        if tap and p.returncode == 0:
            # local import: clone owns the tap lifecycle (create on clone, delete here)
            from vmctl_core.clone import delete_ppc_tap

            delete_ppc_tap(tap)
