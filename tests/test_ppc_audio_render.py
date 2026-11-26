"""ppc/mac99 (screamer): exactly ONE audiodev, the libvirt <audio> element (id audio1), and the
onboard screamer bound to it by name. QEMU 7.2 bound it to the first audiodev and ignored a
duplicate id, so a second -audiodev in qemu:commandline silently never played; QEMU >= 8.2 has no
such fallback and exits with "no default audio driver available" unless screamer.audiodev is set."""

from __future__ import annotations

import itertools
import xml.etree.ElementTree as ET
from pathlib import Path

from vmctl_core.catalog import BaseImage, Hardware
from vmctl_core.clone import render_domain_xml

QNS = "{http://libvirt.org/schemas/domain/qemu/1.0}"


def _render(**hw):
    base = BaseImage(
        id="mac9",
        path="mac9.qcow2",
        os="mac-os-9.2.2",
        hw=Hardware(arch="ppc", machine="mac99", memory_mb=512, **hw),
    )
    root = ET.fromstring(
        render_domain_xml(
            base,
            name="m1",
            disk_path=Path("/c/m1.qcow2"),
            pulse_server="unix:/run/user/1000/pulse/native",
        )
    )
    args = [a.get("value") for a in root.iter(f"{QNS}arg")]
    return root.findall("./devices/audio"), args


def test_silent_ppc_has_one_none_audiodev():
    audio, args = _render()
    assert [(a.get("id"), a.get("type")) for a in audio] == [("1", "none")]
    assert "-audiodev" not in args


def test_audio_sink_renders_a_pulseaudio_audio_element():
    audio, args = _render(audio_sink="rvmc-abc123")
    assert len(audio) == 1 and audio[0].get("type") == "pulseaudio"
    assert audio[0].get("serverName") == "unix:/run/user/1000/pulse/native"
    assert audio[0].find("output").get("name") == "rvmc-abc123"
    assert "-audiodev" not in args


def _pairs(args):
    return list(itertools.pairwise(args))


def test_screamer_is_bound_to_audio1_silent_and_with_sink():
    for hw in ({}, {"audio_sink": "rvmc-abc123"}):
        _, args = _render(**hw)
        assert ("-global", "screamer.audiodev=audio1") in _pairs(args)
