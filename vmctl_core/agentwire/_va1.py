# Vendored from vmctl-guest-agent c6db1f46e002f09e670da11e4a363e77d519326f:contract/va1.py
"""VA1 byte codec. Compatible with Python 2.3 and Python 3.4+.

Metadata accepts ASCII strings or bytes; values and payloads must be bytes
(str on Python 2). Decoded metadata and ordered key/value pairs are bytes.
FrameError.code is text, FrameError.id is bytes or None. EOF is StopIteration.
"""
import binascii
import sys


def _bytes(text):
    if isinstance(text, type(''.encode('latin1'))):
        return text
    return text.encode('latin1')


EMPTY = _bytes('')
LF = _bytes('\n')
MARKER = _bytes('\x02VA1 ')
HEX = _bytes('0123456789ABCDEF')
TYPES = [_bytes(x) for x in ('CALL', 'OK', 'ERR', 'BEAT')]
KINDS = [_bytes(x) for x in ('-', 'rows', 'raw')]
CODES = ('bad_frame', 'crc', 'too_large', 'unknown_tool', 'unsupported',
         'bad_args', 'not_found', 'denied', 'exists', 'timeout', 'busy',
         'failed', 'internal')


class FrameError(Exception):
    def __init__(self, code, id=None):
        Exception.__init__(self, code)
        self.code = code
        self.id = id


def _bad():
    raise FrameError('bad_frame')


def _valid(value, alphabet, minimum, maximum):
    if not minimum <= len(value) <= maximum:
        return False
    for i in range(len(value)):
        if value[i:i + 1] not in alphabet:
            return False
    return True


def _key(key):
    return _valid(key, _bytes('abcdefghijklmnopqrstuvwxyz0123456789_.'),
                  1, len(key))


def _metadata(id, type, kind):
    if (not _valid(id, _bytes('0123456789abcdefghijklmnopqrstuvwxyz'), 1, 16)
            or type not in TYPES or kind not in KINDS
            or (type == _bytes('BEAT') and id != _bytes('0'))):
        _bad()


def escape(value):
    parts = []
    for i in range(len(value)):
        c = value[i:i + 1]
        n = ord(c)
        if n < 32 or n == 127 or n == 37:
            parts.append(_bytes('%%%02X' % n))
        else:
            parts.append(c)
    return EMPTY.join(parts)


def unescape(value):
    parts = []
    i = 0
    while i < len(value):
        c = value[i:i + 1]
        if c == _bytes('%'):
            digits = value[i + 1:i + 3]
            if not _valid(digits, HEX, 2, 2):
                _bad()
            parts.append(_bytes(chr(int(digits, 16))))
            i = i + 3
        else:
            if ord(c) < 32 or ord(c) == 127:
                _bad()
            parts.append(c)
            i = i + 1
    return EMPTY.join(parts)


def _pairs(kv):
    if hasattr(kv, 'items'):
        return kv.items()
    return kv


def encode_kv(kv):
    lines = []
    seen = {}
    for key, value in _pairs(kv):
        key = _bytes(key)
        if not _key(key) or key in seen:
            _bad()
        seen[key] = True
        lines.append(key + _bytes('=') + escape(value) + LF)
    return EMPTY.join(lines) + LF


def decode_body(kind, body):
    pairs = []
    seen = {}
    pos = 0
    while True:
        end = body.find(LF, pos)
        if end < 0:
            _bad()
        line = body[pos:end]
        pos = end + 1
        if not line:
            break
        split = line.find(_bytes('='))
        if split < 1 or not _key(line[:split]) or line[:split] in seen:
            _bad()
        seen[line[:split]] = True
        pairs.append((line[:split], unescape(line[split + 1:])))
    payload = body[pos:]
    kind = _bytes(kind)
    if kind == _bytes('-'):
        if payload:
            _bad()
    elif kind == _bytes('rows'):
        decode_rows(payload)
    elif kind != _bytes('raw'):
        _bad()
    return pairs, payload


def _columns(columns):
    seen = {}
    for name in columns:
        if not name or name in seen:
            _bad()
        seen[name] = True


def encode_rows(columns, rows):
    lines = []
    width = len(columns)
    _columns(columns)
    if width == 0:
        _bad()
    for row in [columns] + list(rows):
        if len(row) != width:
            _bad()
        lines.append(_bytes('\t').join([escape(x) for x in row]) + LF)
    return EMPTY.join(lines)


def decode_rows(payload):
    if not payload or payload[-1:] != LF:
        _bad()
    rows = []
    for line in payload[:-1].split(LF):
        row = [unescape(x) for x in line.split(_bytes('\t'))]
        if rows and len(row) != len(rows[0]):
            _bad()
        rows.append(row)
    _columns(rows[0])
    return rows[0], rows[1:]


def numbered_kv(values, prefix='arg'):
    prefix = _bytes(prefix)
    pairs = []
    for i in range(len(values)):
        key = prefix + _bytes('.%d' % i)
        if not _key(key):
            _bad()
        pairs.append((key, values[i]))
    return pairs


def numbered_list(kv, prefix='arg'):
    prefix = _bytes(prefix) + _bytes('.')
    found = {}
    seen = {}
    for key, value in _pairs(kv):
        key = _bytes(key)
        if not _key(key) or key in seen:
            _bad()
        seen[key] = True
        if key[:len(prefix)] != prefix:
            continue
        index = key[len(prefix):]
        if (not _valid(index, _bytes('0123456789'), 1, len(index))
                or (len(index) > 1 and index[:1] == _bytes('0'))
                or index in found):
            _bad()
        found[index] = value
    values = []
    for i in range(len(found)):
        index = _bytes(str(i))
        if index not in found:
            _bad()
        values.append(found[index])
    return values


def _crc32(data):
    # Python 2.3 on 32-bit hosts parses 0xffffffff as -1 (PEP 237).
    return (binascii.crc32(data) & 0xffffffff) % 4294967296


def encode_frame(id, type, kv, payload_kind, payload):
    id, type, kind = _bytes(id), _bytes(type), _bytes(payload_kind)
    _metadata(id, type, kind)
    body = encode_kv(kv) + payload
    decode_body(kind, body)
    header = (MARKER + id + _bytes(' ') + type + _bytes(' ') + kind
              + _bytes(' %d %08x\n' % (len(body), _crc32(body))))
    if len(header) > 128:
        _bad()
    return header + body + LF


class FrameReader:
    """read_fn(n) returns up to n bytes; empty means EOF. Retry next after errors."""
    def __init__(self, read_fn, max_frame):
        if max_frame < 0:
            raise ValueError('negative max_frame')
        self.read_fn = read_fn
        self.max_frame = max_frame
        self.pending = EMPTY

    def _read(self, n):
        if self.pending:
            result = self.pending[:n]
            self.pending = self.pending[n:]
            return result
        return self.read_fn(n)

    def _exact(self, n, id, drop=False):
        parts = []
        while n:
            part = self._read(min(n, 4096))
            if not part:
                raise FrameError('bad_frame', id)
            n = n - len(part)
            if not drop:
                parts.append(part)
        return EMPTY.join(parts)

    def next(self):
        match = 0
        while match < len(MARKER):
            c = self._read(1)
            if not c:
                raise StopIteration
            if c == MARKER[match:match + 1]:
                match = match + 1
            elif c == MARKER[:1]:
                match = 1
            else:
                match = 0
        header = MARKER
        while len(header) < 128:
            c = self._exact(1, None)
            header = header + c
            if c == LF:
                break
        if header[-1:] != LF:
            _bad()
        header = header[:-1]
        if header[-1:] == _bytes('\r'):
            header = header[:-1]
        fields = header.split(_bytes(' '))
        if len(fields) != 6:
            _bad()
        marker, id, type, kind, length, crc = fields
        _metadata(id, type, kind)
        if (not _valid(length, _bytes('0123456789'), 1, len(length))
                or not _valid(crc, _bytes('0123456789abcdef'), 8, 8)):
            _bad()
        length = int(length)
        if length > self.max_frame:
            self._exact(length, id, True)
            self._exact(1, id, True)
            raise FrameError('too_large', id)
        body = self._exact(length, id)
        trailer = self._exact(1, id)
        if trailer != LF:
            self.pending = trailer
            raise FrameError('bad_frame', id)
        if _crc32(body) != int(crc, 16):
            raise FrameError('crc', id)
        try:
            kv, payload = decode_body(kind, body)
        except FrameError:
            raise FrameError('bad_frame', id)
        return id, type, kv, kind, payload

    __next__ = next

    def __iter__(self):
        return self


class ReplyCache:
    """One cache per agent process, shared across streams; serialize access.

    Keep 64 completed ids in completion order; replay does not refresh order.
    Running ids are never evicted. Identity is id alone, regardless of body.
    """
    def __init__(self):
        self.running = {}
        self.replies = {}
        self.order = []

    def begin(self, id):
        id = _bytes(id)
        _metadata(id, _bytes('CALL'), _bytes('-'))
        if id in self.running:
            return 'busy', None
        if id in self.replies:
            return 'replay', self.replies[id]
        self.running[id] = True
        return 'new', None

    def finish(self, id, reply):
        id = _bytes(id)
        if id not in self.running:
            raise ValueError('id is not running')
        del self.running[id]
        self.replies[id] = reply
        self.order.append(id)
        if len(self.order) > 64:
            del self.replies[self.order.pop(0)]


def error_frame(id, code, msg, kv=()):
    if code not in CODES:
        raise ValueError('unknown error code')
    pairs = [(_bytes('code'), _bytes(code)), (_bytes('msg'), msg)]
    for key, value in _pairs(kv):
        key = _bytes(key)
        if key in (_bytes('code'), _bytes('msg')):
            raise ValueError('reserved error field')
        pairs.append((key, value))
    return encode_frame(id, 'ERR', pairs, '-', EMPTY)


def self_test():
    assert _crc32(_bytes('123456789')) == 3421780262
    raw = EMPTY.join([_bytes(chr(i)) for i in range(256)])
    kv = [(_bytes('value'), raw)]
    wire = encode_frame('a', 'OK', kv, 'raw', raw)
    class Input:
        def __init__(self, data):
            self.data = data
        def read(self, n):
            part = self.data[:min(n, 3)]
            self.data = self.data[len(part):]
            return part
    reader = FrameReader(Input(wire).read, 4096)
    assert reader.next() == (_bytes('a'), _bytes('OK'), kv, _bytes('raw'), raw)
    assert unescape(escape(raw)) == raw
    table = encode_rows([_bytes('a')], [[raw]])
    assert decode_rows(table) == ([_bytes('a')], [[raw]])
    assert numbered_list(numbered_kv([raw, EMPTY])) == [raw, EMPTY]
    cache = ReplyCache()
    assert cache.begin('a') == ('new', None)
    assert cache.begin('a') == ('busy', None)
    cache.finish('a', wire)
    assert cache.begin('a') == ('replay', wire)
    assert FrameReader(Input(error_frame('a', 'busy', EMPTY)).read, 4096).next()[1] == _bytes('ERR')
    broken = wire[:wire.find(LF)].split(_bytes(' '))
    broken[-1] = _bytes('00000000')
    broken = _bytes(' ').join(broken) + wire[wire.find(LF):]
    reader = FrameReader(Input(broken + wire).read, 4096)
    try:
        reader.next()
        assert False
    except FrameError:
        assert sys.exc_info()[1].code == 'crc'
    assert reader.next()[-1] == raw
    for i in range(65):
        id = str(i)
        assert cache.begin(id) == ('new', None)
        cache.finish(id, wire)
    assert cache.begin('0') == ('new', None)
    assert cache.begin('1') == ('replay', wire)
    huge = _bytes('\x02VA1 huge OK raw ' + '9' * 80 + ' 00000000\n')
    try:
        FrameReader(Input(huge).read, 4096).next()
        assert False
    except FrameError:
        assert sys.exc_info()[1].code == 'bad_frame'
    sys.stdout.write('VA1 self-test OK: Python %s\n' % sys.version.split()[0])


if __name__ == '__main__':
    self_test()
