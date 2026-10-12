"""Bounded CTAP canonical CBOR subset, not a general-purpose CBOR library."""
MAX_BYTES = 4096
MAX_ITEMS = 512
MAX_DEPTH = 8

class CborError(ValueError):
    pass

def _head(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    for marker, width in [(24, 1), (25, 2), (26, 4), (27, 8)]:
        if value < 1 << (width * 8):
            return bytes([(major << 5) | marker]) + value.to_bytes(width, "big")
    raise CborError("integer out of range")

def encode(value):
    if value is False: return b"\xf4"
    if value is True: return b"\xf5"
    if value is None: return b"\xf6"
    if type(value) is int:
        return _head(0 if value >= 0 else 1, value if value >= 0 else -1-value)
    if type(value) is bytes: return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if type(value) is list:
        return _head(4, len(value)) + b"".join(encode(item) for item in value)
    if type(value) is dict:
        items = [(encode(key), encode(item)) for key, item in value.items()]
        items.sort(key=lambda item: (len(item[0]), item[0]))
        return _head(5, len(items)) + b"".join(k+v for k,v in items)
    raise CborError("unsupported CBOR value")

class Reader:
    def __init__(self, raw):
        if type(raw) is not bytes or len(raw) > MAX_BYTES: raise CborError("CBOR size")
        self.raw, self.pos, self.items = raw, 0, 0
    def take(self, length):
        if self.pos + length > len(self.raw): raise CborError("truncated CBOR")
        out = self.raw[self.pos:self.pos+length]
        self.pos += length
        return out
    def item(self, depth=0):
        self.items += 1
        if depth > MAX_DEPTH or self.items > MAX_ITEMS: raise CborError("CBOR bounds")
        first = self.take(1)[0]
        major, extra = first >> 5, first & 31
        if major == 7:
            if extra in (20,21,22): return {20:False,21:True,22:None}[extra]
            raise CborError("unsupported simple/float CBOR")
        if major > 5: raise CborError("CBOR tags unsupported")
        if extra < 24: size = extra
        elif extra in (24,25,26,27):
            width = 1 << (extra - 24)
            size = int.from_bytes(self.take(width), "big")
            if size < {1:24,2:256,4:65536,8:4294967296}[width]: raise CborError("nonminimal CBOR")
        else: raise CborError("indefinite/reserved CBOR")
        if major == 0: return size
        if major == 1: return -1-size
        if size > MAX_BYTES: raise CborError("CBOR bounds")
        if major == 2: return self.take(size)
        if major == 3:
            try: return self.take(size).decode("utf-8", "strict")
            except UnicodeError as error: raise CborError("invalid UTF-8") from error
        if size > MAX_ITEMS: raise CborError("container bounds")
        if major == 4: return [self.item(depth+1) for _ in range(size)]
        result, last = {}, None
        for _ in range(size):
            start = self.pos
            key = self.item(depth+1)
            encoded = self.raw[start:self.pos]
            order = (len(encoded), encoded)
            if type(key) not in (int, str, bytes) or (last is not None and order <= last):
                raise CborError("invalid, duplicate, or unordered key")
            last = order
            result[key] = self.item(depth+1)
        return result

def decode(raw):
    reader = Reader(raw)
    result = reader.item()
    if reader.pos != len(raw): raise CborError("trailing CBOR")
    return result
