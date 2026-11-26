"""qemu-ga probe gate: no agent call unless the qemu-ga channel exists and is connected.

libvirt rejects an agent query on a domain without the channel ("not configured") or with
a disconnected channel ("not connected") and logs each rejection as error. The polling
paths (guest_ip, guest_ping, net_info) must not issue the query in those cases.
"""

from __future__ import annotations

import subprocess

import pytest

from vmctl_core.backends.libvirt_backend import LibvirtBackend

_XML = """<domain><os><type arch='x86_64'>hvm</type></os><devices>{chan}</devices></domain>"""
_CHAN = (
    "<channel type='unix'><target type='virtio' name='org.qemu.guest_agent.0'{state}/></channel>"
)
NO_CHANNEL = _XML.format(chan="")
DISCONNECTED = _XML.format(chan=_CHAN.format(state=" state='disconnected'"))
CONNECTED = _XML.format(chan=_CHAN.format(state=" state='connected'"))


def _backend(xml):
    b = LibvirtBackend("d")
    calls: list[tuple] = []

    def virsh(*args, **kw):
        calls.append(args)
        out = '{"return": {}}' if args[0] == "qemu-agent-command" else ""
        return subprocess.CompletedProcess(args, 0, out, "")

    b._virsh = virsh  # type: ignore[method-assign]
    b.dumpxml = lambda: xml  # type: ignore[method-assign]
    b.discover_vm_network = lambda: None  # type: ignore[method-assign]
    return b, calls


def _agent_calls(calls):
    return [c for c in calls if "agent" in c or c[0] == "qemu-agent-command"]


def _exercise(b):
    b.guest_ip()
    ping = b.guest_ping()
    info = b.net_info()
    return ping, info


@pytest.mark.parametrize("xml", [NO_CHANNEL, DISCONNECTED])
def test_no_agent_call_without_connected_channel(xml):
    b, calls = _backend(xml)
    ping, info = _exercise(b)
    assert _agent_calls(calls) == []
    assert ping is False
    assert info["interfaces"] == []
    # lease/arp are still asked
    assert ("domifaddr", "d", "--source", "lease") in calls


def test_agent_queried_when_connected():
    b, calls = _backend(CONNECTED)
    ping, _ = _exercise(b)
    assert ping is True
    assert ("domifaddr", "d", "--source", "agent") in calls
    assert any(c[0] == "qemu-agent-command" for c in calls)


def test_dumpxml_error_means_unavailable():
    b, _ = _backend(CONNECTED)
    b.dumpxml = lambda: "<not xml"  # type: ignore[method-assign]
    assert b._agent_available() is False
