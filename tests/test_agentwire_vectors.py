"""Golden streams copied byte-for-byte from the pinned VA1 reference codec."""

import hashlib
import io
from pathlib import Path

import pytest

from vmctl_core.agentwire import _va1

VECTORS = Path(__file__).with_name("agentwire_vectors")


@pytest.mark.parametrize("path", sorted(VECTORS.glob("*.wire")), ids=lambda p: p.stem)
@pytest.mark.parametrize("chunk", (1, 2, 5, 31, 4096))
def test_vectors(path, chunk):
    source = io.BytesIO(path.read_bytes())
    reader = _va1.FrameReader(lambda n: source.read(min(n, chunk)), 4096)
    events = []
    while True:
        try:
            ident, frame_type, kv, kind, payload = reader.next()
        except StopIteration:
            break
        except _va1.FrameError as error:
            events.append(b"E " + error.code.encode() + b" " + (error.id or b"-") + b"\n")
            continue
        if kind == b"rows":
            payload = _va1.encode_rows(*_va1.decode_rows(payload))
        wire = _va1.encode_frame(ident, frame_type, kv, kind, payload)
        events.append(b"F " + wire.hex().encode() + b"\n")
    assert b"".join(events) == path.with_suffix(".out").read_bytes()


def test_vendor_hashes():
    # A refresh must deliberately update both the source pin and this manifest.
    lines = (VECTORS / "SHA256SUMS").read_text().splitlines()
    for line in lines:
        digest, name = line.split(maxsplit=1)
        if name == "_va1.py":
            data = Path(_va1.__file__).read_bytes().split(b"\n", 1)[1]
        else:
            data = (VECTORS / name).read_bytes()
        assert hashlib.sha256(data).hexdigest() == digest, name


def test_codec_all_bytes_and_numbered_lists():
    raw = bytes(range(256))
    assert _va1.unescape(_va1.escape(raw)) == raw
    assert _va1.decode_rows(_va1.encode_rows([raw], [[raw]])) == ([raw], [[raw]])
    assert _va1.numbered_list(_va1.numbered_kv([raw, b""])) == [raw, b""]
    for keys in ({"arg.1": b"x"}, {"arg.00": b"x"}, {"arg.-1": b"x"}):
        with pytest.raises(_va1.FrameError):
            _va1.numbered_list(keys)


def test_cache_completion_order_and_replay_does_not_refresh():
    cache = _va1.ReplyCache()
    for i in range(65):
        assert cache.begin(str(i)) == ("new", None)
    for i in reversed(range(1, 65)):
        cache.finish(str(i), str(i).encode())
    assert cache.begin("0") == ("busy", None)
    assert cache.begin("64") == ("replay", b"64")
    cache.finish("0", b"0")
    assert cache.begin("64") == ("new", None)
    assert cache.begin("63") == ("replay", b"63")
