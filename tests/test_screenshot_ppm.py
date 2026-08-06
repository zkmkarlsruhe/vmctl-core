"""Arch-portable framebuffer capture (research/64).

``virsh screenshot`` asks qemu to emit a PNG, which the screamer-qemu PPC fork
(mac9 / Tiger / Snow Leopard) cannot do — that build has no libpng and answers
``Enable PNG support with libpng for screendump``. The QMP backstop must work on
exactly those guests, so ``LibvirtBackend.screenshot`` now drives the monitor's
default ``screendump`` (a PPM — no libpng) and encodes the PNG host-side with the
stdlib. These tests cover the PPM->PNG encoder and the mocked capture path.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from vmctl_core.backends import BackendError, LibvirtBackend
from vmctl_core.backends.libvirt_backend import ppm_to_png


def _make_ppm(width: int, height: int, comment: bool = False) -> bytes:
    """A synthetic 8-bit P6 PPM whose pixels encode a (x+y) gradient."""
    header = b"P6\n"
    if comment:
        header += b"# qemu screendump\n"
    header += f"{width} {height}\n255\n".encode()
    raster = bytearray()
    for y in range(height):
        for x in range(width):
            raster += bytes(((x * 3) & 0xFF, (y * 5) & 0xFF, (x + y) & 0xFF))
    return header + bytes(raster)


def _png_dims(png: bytes) -> tuple[int, int]:
    """Parse width/height out of a PNG's IHDR — also asserts the signature/chunk."""
    assert png[:8] == b"\x89PNG\r\n\x1a\n"
    length = struct.unpack(">I", png[8:12])[0]
    assert png[12:16] == b"IHDR" and length == 13
    return struct.unpack(">II", png[16:24])


def _decode_png_rgb(png: bytes, width: int, height: int) -> bytes:
    """Inflate the IDAT of a filter-0 RGB PNG back to raw RGB bytes."""
    i = 8
    idat = b""
    while i < len(png):
        length = struct.unpack(">I", png[i : i + 4])[0]
        tag = png[i + 4 : i + 8]
        payload = png[i + 8 : i + 8 + length]
        # CRC must be correct
        assert struct.unpack(">I", png[i + 8 + length : i + 12 + length])[0] == (
            zlib.crc32(tag + payload) & 0xFFFFFFFF
        )
        if tag == b"IDAT":
            idat += payload
        i += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 3
    out = bytearray()
    for y in range(height):
        assert raw[y * (stride + 1)] == 0  # filter-type byte 0 (none)
        out += raw[y * (stride + 1) + 1 : y * (stride + 1) + 1 + stride]
    return bytes(out)


def test_ppm_to_png_roundtrip_pixels_preserved():
    w, h = 7, 5
    ppm = _make_ppm(w, h)
    png = ppm_to_png(ppm)
    assert _png_dims(png) == (w, h)
    # the raster after the header must survive the encode byte-for-byte
    original = ppm[ppm.index(b"255\n") + 4 :]
    assert _decode_png_rgb(png, w, h) == original


def test_ppm_to_png_handles_header_comment():
    png = ppm_to_png(_make_ppm(4, 3, comment=True))
    assert _png_dims(png) == (4, 3)


def test_ppm_to_png_rejects_non_p6():
    with pytest.raises(BackendError, match="P6"):
        ppm_to_png(b"\x89PNG\r\n\x1a\n....")


def test_ppm_to_png_rejects_unsupported_maxval():
    with pytest.raises(BackendError, match="maxval"):
        ppm_to_png(b"P6\n2 2\n65535\n" + b"\x00" * 24)


def test_ppm_to_png_rejects_truncated_raster():
    with pytest.raises(BackendError, match="truncated"):
        ppm_to_png(b"P6\n4 4\n255\n" + b"\x00" * 10)


def test_screenshot_uses_screendump_not_virsh_screenshot(monkeypatch):
    """screenshot() must drive HMP ``screendump`` (arch-portable) — never
    ``virsh screenshot`` (needs libpng) — and return PNG bytes."""
    be = LibvirtBackend("dom-ppc")
    calls: list[tuple[str, ...]] = []
    ppm = _make_ppm(6, 4)

    def fake_virsh(*args: str, timeout: float = 30.0, check: bool = True):
        calls.append(args)
        assert args[0] == "qemu-monitor-command"
        assert args[2] == "--hmp"
        # the HMP command is ``screendump <tmpfile>``; emulate qemu writing the PPM
        assert args[3].startswith("screendump ")
        path = args[3].split(" ", 1)[1]
        with open(path, "wb") as f:
            f.write(ppm)

        class P:
            stdout = ""
            stderr = ""
            returncode = 0

        return P()

    monkeypatch.setattr(be, "_virsh", fake_virsh)
    out = be.screenshot()
    assert out[:8] == b"\x89PNG\r\n\x1a\n"
    assert _png_dims(out) == (6, 4)
    assert all(c[0] == "qemu-monitor-command" for c in calls)
    assert not any(c[0] == "screenshot" for c in calls)


def test_screenshot_raises_when_screendump_writes_nothing(monkeypatch):
    """A build that cannot dump the framebuffer leaves no file → clear BackendError
    (which qmp_backstop turns into a structured error, not a traceback)."""
    be = LibvirtBackend("dom-broken")

    def fake_virsh(*args: str, timeout: float = 30.0, check: bool = True):
        class P:
            stdout = "unable to open screendump target"
            stderr = ""
            returncode = 0

        return P()  # never writes the file

    monkeypatch.setattr(be, "_virsh", fake_virsh)
    with pytest.raises(BackendError, match="screendump produced no output"):
        be.screenshot()
