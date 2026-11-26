"""Native screenshot header checks without third-party image decoders."""

import binascii
import struct


class UnsupportedImageFormat(ValueError):
    """The image format has no header validator."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def image_header(format: str, width: int, height: int, data: bytes) -> None:
    """Validate common native image headers without third-party decoders."""
    format = format.lower()
    dimensions: tuple[int, int] | None = None
    if format == "png":
        _require(
            len(data) >= 33 and data[:8] == b"\x89PNG\r\n\x1a\n" and data[8:16] == b"\0\0\0\rIHDR",
            "invalid PNG header",
        )
        dimensions = struct.unpack("!II", data[16:24])
        _require(
            binascii.crc32(data[12:29]) == int.from_bytes(data[29:33]),
            "invalid PNG IHDR checksum",
        )
    elif format == "bmp":
        _require(len(data) >= 26 and data[:2] == b"BM", "invalid BMP header")
        size = struct.unpack_from("<I", data, 14)[0]
        if size == 12:
            dimensions = struct.unpack_from("<HH", data, 18)
        else:
            _require(size >= 40 and len(data) >= 54, "invalid BMP DIB header")
            w, h = struct.unpack_from("<ii", data, 18)
            dimensions = (w, abs(h))
    elif format == "gif":
        _require(len(data) >= 13 and data[:6] in (b"GIF87a", b"GIF89a"), "invalid GIF header")
        dimensions = struct.unpack_from("<HH", data, 6)
    elif format == "pict":
        # PICT files have a 512-byte prefix; raw QuickDraw pictures omit it.
        for start in (0, 512):
            version = data[start + 10 : start + 14]
            if version[:2] == b"\x11\x01" or version == b"\x00\x11\x02\xff":
                if version == b"\x00\x11\x02\xff":
                    _require(
                        len(data) >= start + 40 and data[start + 14 : start + 16] == b"\x0c\x00",
                        "invalid PICT v2 header",
                    )
                top, left, bottom, right = struct.unpack_from(">hhhh", data, start + 2)
                dimensions = (right - left, bottom - top)
                break
        _require(dimensions is not None, "invalid PICT header")
    elif format in ("ppm", "pgm", "pbm"):
        # Netpbm header tokens can be separated by whitespace and comments.
        import re

        tokens = re.findall(rb"[^\s#]+|#[^\n]*(?:\n|$)", data)
        tokens = [token for token in tokens if not token.startswith(b"#")]
        _require(
            len(tokens) >= 3 and tokens[0] in (b"P1", b"P2", b"P3", b"P4", b"P5", b"P6"),
            "invalid Netpbm header",
        )
        dimensions = (int(tokens[1]), int(tokens[2]))
    elif format in ("jpg", "jpeg"):
        _require(len(data) >= 4 and data[:2] == b"\xff\xd8", "invalid JPEG header")
        pos = 2
        while pos + 4 <= len(data):
            _require(data[pos] == 255, "invalid JPEG marker")
            marker = data[pos + 1]
            if marker == 255:
                pos += 1
                continue
            length = int.from_bytes(data[pos + 2 : pos + 4])
            _require(length >= 2 and pos + 2 + length <= len(data), "truncated JPEG segment")
            if marker in (0xC0, 0xC1, 0xC2):
                _require(length >= 8, "invalid JPEG frame header")
                dimensions = (
                    int.from_bytes(data[pos + 7 : pos + 9]),
                    int.from_bytes(data[pos + 5 : pos + 7]),
                )
                break
            pos += 2 + length
        _require(dimensions is not None, "missing JPEG frame header")
    else:
        raise UnsupportedImageFormat(f"image header validator unavailable for {format}")
    _require(dimensions == (width, height), "image dimensions differ from reply")
