"""Re-inserting the same ISO on a ppc domain closes a tray the guest opened (OS 9 eject)."""

import json
import types

from vmctl_core.backends.libvirt_backend import LibvirtBackend


def test_reinsert_same_iso_closes_open_tray():
    be = object.__new__(LibvirtBackend)
    be.name = "d"
    calls = []

    def virsh(*args, **kw):
        calls.append(args)
        out = ""
        if args[-1] == '{"execute":"query-block"}':
            out = json.dumps(
                {
                    "return": [
                        {
                            "device": "ide1-cd1",
                            "removable": True,
                            "tray_open": True,
                            "inserted": {"file": "/isos/x.iso"},
                        },
                        {"device": "ide0-hd0", "removable": False},
                    ]
                }
            )
        return types.SimpleNamespace(stdout=out, stderr="", returncode=0)

    be._virsh = virsh
    be._is_ppc = lambda: True
    be._ppc_set_cdrom = lambda iso: False  # same ISO already attached, no reboot
    be.is_running = lambda: True
    be.insert_cd("/isos/x.iso")
    closes = [json.loads(a[-1]) for a in calls if "blockdev-close-tray" in a[-1]]
    assert closes == [{"execute": "blockdev-close-tray", "arguments": {"device": "ide1-cd1"}}]
