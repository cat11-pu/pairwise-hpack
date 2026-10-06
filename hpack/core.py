"""An HPACK (RFC 7541) header compression kernel built on the standard library.

Nothing here touches a socket or a file.  A caller hands a header block to a
:class:`Decoder` and gets the header list back, or gives a header list to an
:class:`Encoder` and gets the block that carries it.  Each side keeps a dynamic
table of its own, the way the two peers of an HTTP/2 connection do.
"""

#: Size a fresh dynamic table starts with (the SETTINGS_HEADER_TABLE_SIZE
#: default of RFC 7540).
DEFAULT_TABLE_SIZE = 4096

#: What a dynamic table entry costs on top of the octets of its name and value.
ENTRY_OVERHEAD = 32

#: Field names whose values must never be kept in a dynamic table.
SENSITIVE_NAMES = frozenset(("authorization", "cookie", "proxy-authorization"))


class HPACKError(Exception):
    """Raised when a header block does not follow the HPACK format."""

# -- The static table (RFC 7541 Appendix A) ---------------------------------

STATIC_TABLE = (
    (":authority", ""), (":method", "GET"), (":method", "POST"),
    (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
    (":scheme", "https"), (":status", "200"), (":status", "204"),
    (":status", "206"), (":status", "304"), (":status", "400"),
    (":status", "404"), (":status", "500"), ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
    ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""),
    ("age", ""), ("allow", ""), ("authorization", ""), ("cache-control", ""),
    ("content-disposition", ""), ("content-encoding", ""),
    ("content-language", ""), ("content-length", ""), ("content-location", ""),
    ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""),
    ("etag", ""), ("expect", ""), ("expires", ""), ("from", ""), ("host", ""),
    ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""),
    ("if-range", ""), ("if-unmodified-since", ""), ("last-modified", ""),
    ("link", ""), ("location", ""), ("max-forwards", ""),
    ("proxy-authenticate", ""), ("proxy-authorization", ""), ("range", ""),
    ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""),
    ("set-cookie", ""), ("strict-transport-security", ""),
    ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""),
    ("www-authenticate", ""),
)


def _static_name_index(name):
    """Index of the first static entry carrying this name, or None."""
    for index, entry in enumerate(STATIC_TABLE, 1):
        if entry[0] == name:
            return index
    return None

# -- The Huffman code (RFC 7541 Appendix B) ---------------------------------

#: The code of every octet, eight hex digits per symbol, in symbol order.
_HUFFMAN_CODES = (
    "00001ff8007fffd80fffffe20fffffe30fffffe40fffffe50fffffe60fffffe70fffffe800ffffea3ffffffc0fffffe90fffffea3fff"
    "fffd0fffffeb0fffffec0fffffed0fffffee0fffffef0ffffff00ffffff10ffffff23ffffffe0ffffff30ffffff40ffffff50ffffff6"
    "0ffffff70ffffff80ffffff90ffffffa0ffffffb00000014000003f8000003f900000ffa00001ff900000015000000f8000007fa0000"
    "03fa000003fb000000f9000007fb000000fa000000160000001700000018000000000000000100000002000000190000001a0000001b"
    "0000001c0000001d0000001e0000001f0000005c000000fb00007ffc0000002000000ffb000003fc00001ffa000000210000005d0000"
    "005e0000005f000000600000006100000062000000630000006400000065000000660000006700000068000000690000006a0000006b"
    "0000006c0000006d0000006e0000006f000000700000007100000072000000fc00000073000000fd00001ffb0007fff000001ffc0000"
    "3ffc0000002200007ffd0000000300000023000000040000002400000005000000250000002600000027000000060000007400000075"
    "00000028000000290000002a000000070000002b000000760000002c00000008000000090000002d0000007700000078000000790000"
    "007a0000007b00007ffe000007fc00003ffd00001ffd0ffffffc000fffe6003fffd2000fffe7000fffe8003fffd3003fffd4003fffd5"
    "007fffd9003fffd6007fffda007fffdb007fffdc007fffdd007fffde00ffffeb007fffdf00ffffec00ffffed003fffd7007fffe000ff"
    "ffee007fffe1007fffe2007fffe3007fffe4001fffdc003fffd8007fffe5003fffd9007fffe6007fffe700ffffef003fffda001fffdd"
    "000fffe9003fffdb003fffdc007fffe8007fffe9001fffde007fffea003fffdd003fffde00fffff0001fffdf003fffdf007fffeb007f"
    "ffec001fffe0001fffe1003fffe0001fffe2007fffed003fffe1007fffee007fffef000fffea003fffe2003fffe3003fffe4007ffff0"
    "003fffe5003fffe6007ffff103ffffe003ffffe1000fffeb0007fff1003fffe7007ffff2003fffe801ffffec03ffffe203ffffe303ff"
    "ffe407ffffde07ffffdf03ffffe500fffff101ffffed0007fff2001fffe303ffffe607ffffe007ffffe103ffffe707ffffe200fffff2"
    "001fffe4001fffe503ffffe803ffffe90ffffffd07ffffe307ffffe407ffffe5000fffec00fffff3000fffed001fffe6003fffe9001f"
    "ffe7001fffe8007ffff3003fffea003fffeb01ffffee01ffffef00fffff400fffff503ffffea007ffff403ffffeb07ffffe603ffffec"
    "03ffffed07ffffe707ffffe807ffffe907ffffea07ffffeb0ffffffe07ffffec07ffffed07ffffee07ffffef07fffff003ffffee"
)

#: The bit length of every code, two hex digits per symbol, in symbol order.
_HUFFMAN_LENGTHS = (
    "0d171c1c1c1c1c1c1c181e1c1c1e1c1c1c1c1c1c1c1c1e1c1c1c1c1c1c1c1c1c060a0a0c0d06080b0a0a080b08060606050505060606"
    "0606060607080f060c0a0d06070707070707070707070707070707070707070707070807080d130d0e060f0506050605060606050707"
    "0606060506070605050607070707070f0b0e0d1c14161414161616171617171717171817181816171817171717151617161717181615"
    "1416161717151716161815161717151516151716171714161616171616171a1a1413161716191a1a1a1b1b1a181913151a1b1b1a1b18"
    "15151a1a1c1b1b1b14181415161515171616191918181a171a1b1a1a1b1b1b1b1b1c1b1b1b1b1b1a"
)

#: (code, bit length) of every symbol, with the EOS symbol at the end.
_HUFFMAN = tuple(
    (int(_HUFFMAN_CODES[symbol * 8:symbol * 8 + 8], 16),
     int(_HUFFMAN_LENGTHS[symbol * 2:symbol * 2 + 2], 16))
    for symbol in range(256)
) + ((0x3FFFFFFF, 30),)

_HUFFMAN_BY_CODE = {pair: symbol for symbol, pair in enumerate(_HUFFMAN[:256])}


def huffman_encode(text):
    """Return the Huffman encoding of text, padded with the bits of EOS."""
    accumulator = 0
    bits = 0
    out = bytearray()
    for octet in text.encode("utf-8"):
        code, length = _HUFFMAN[octet]
        accumulator = (accumulator << length) | code
        bits += length
        while bits >= 8:
            bits -= 8
            out.append((accumulator >> bits) & 0xFF)
    if bits:
        free = 8 - bits
        out.append(((accumulator << free) | ((1 << free) - 1)) & 0xFF)
    return bytes(out)


def huffman_decode(data):
    """Return the text a Huffman coded string carries."""
    code = 0
    length = 0
    out = bytearray()
    for octet in data:
        for shift in range(7, -1, -1):
            code = (code << 1) | ((octet >> shift) & 1)
            length += 1
            symbol = _HUFFMAN_BY_CODE.get((code, length))
            if symbol is not None:
                out.append(symbol)
                code = 0
                length = 0
            elif length >= 30:
                raise HPACKError("the string holds no Huffman code")
    if length > 7 or (length and code != (1 << length) - 1):
        raise HPACKError("a Huffman string ends on the bits of the EOS code")
    return out.decode("utf-8")


def huffman_length(text):
    """Return how many octets the Huffman encoding of text takes."""
    bits = sum(_HUFFMAN[octet][1] for octet in text.encode("utf-8"))
    return bits // 8 + 1

# -- Integers and strings (RFC 7541 sections 5.1 and 5.2) -------------------

def encode_integer(value, prefix_bits, prefix=0):
    """Encode an integer into the low bits of a representation."""
    limit = (1 << prefix_bits) - 1
    if value < limit:
        return bytes([prefix | value])
    out = bytearray([prefix | limit])
    value -= limit
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def read_integer(data, offset, prefix_bits):
    """Read an integer, returning it with the offset just past it."""
    limit = (1 << prefix_bits) - 1
    if offset >= len(data):
        raise HPACKError("the block ends in the middle of an integer")
    value = data[offset] & limit
    offset += 1
    if value < limit:
        return value, offset
    shift = 0
    while offset < len(data):
        octet = data[offset]
        offset += 1
        value += (octet & 0x7F) << shift
        shift += 7
        if not octet & 0x80:
            return value, offset
    raise HPACKError("the block ends in the middle of an integer")


def encode_string(text, huffman=True):
    """Encode a string literal, in whichever of the two forms is shorter."""
    raw = text.encode("utf-8")
    if huffman and huffman_length(text) < len(raw):
        payload = huffman_encode(text)
        return encode_integer(len(payload), 7, 0x80) + payload
    return encode_integer(len(raw), 7) + raw


def read_string(data, offset):
    """Read a string literal, returning it with the offset just past it."""
    if offset >= len(data):
        raise HPACKError("the block ends in the middle of a string")
    huffman = bool(data[offset] & 0x80)
    length, offset = read_integer(data, offset, 7)
    if offset + length > len(data):
        raise HPACKError("the block ends in the middle of a string")
    payload = data[offset:offset + length]
    if huffman:
        return huffman_decode(payload), offset + length
    return payload.decode("utf-8"), offset + length

# -- The dynamic table (RFC 7541 section 2.3.2) -----------------------------

class DynamicTable:
    """The table the two peers grow while a connection runs.

    Entries are held oldest first and leave from the front, so the entry that
    arrived last sits at the end of the list and carries the lowest index of
    the dynamic part."""

    def __init__(self, max_size=DEFAULT_TABLE_SIZE):
        self.entries = []
        self.size = 0
        self.max_size = max_size

    def add(self, name, value):
        """Put a field in the table, dropping what no longer fits."""
        entry_size = len(name) + len(value) + ENTRY_OVERHEAD
        while self.entries and self.size + entry_size >= self.max_size:
            self.evict_oldest()
        self.entries.append((name, value))
        self.size += entry_size

    def evict_oldest(self):
        """Drop the entry that has been in the table the longest."""
        name, value = self.entries.pop(0)
        self.size -= len(name) + len(value) + ENTRY_OVERHEAD

    def name_index(self, name):
        """Absolute index of the newest entry carrying this name, or None."""
        for position, entry in enumerate(reversed(self.entries), 1):
            if entry[0] == name:
                return len(STATIC_TABLE) + position
        return None

# -- Decoding ---------------------------------------------------------------

class Decoder:
    """Turns header blocks back into header lists.

    ``max_size`` is the limit negotiated with the peer, so a size update that
    asks for more than that is a protocol error."""

    def __init__(self, max_size=DEFAULT_TABLE_SIZE):
        self.limit = max_size
        self.table = DynamicTable(max_size)

    def decode(self, block):
        """Return the header list a block carries."""
        headers = []
        offset = 0
        while offset < len(block):
            octet = block[offset]
            if octet & 0x80:
                index, offset = read_integer(block, offset, 7)
                headers.append(self._field(index))
            elif octet & 0x40:
                field, offset = self._literal(block, offset, 6, True)
                headers.append(field)
            elif octet & 0x20:
                size, offset = read_integer(block, offset, 5)
                self._resize(size)
            elif octet & 0x10:
                field, offset = self._literal(block, offset, 5, False)
                headers.append(field)
            else:
                field, offset = self._literal(block, offset, 4, True)
                headers.append(field)
        return headers

    def _field(self, index):
        """Return the header field a table index names."""
        if index <= 0:
            raise HPACKError("an indexed field carries no index")
        if index <= len(STATIC_TABLE):
            return STATIC_TABLE[index - 1]
        position = index - len(STATIC_TABLE)
        if position > len(self.table.entries):
            raise HPACKError("table index %d is out of range" % index)
        return self.table.entries[position - 1]

    def _literal(self, block, offset, prefix_bits, indexed):
        """Read a literal field, adding it to the table when indexed."""
        name_index, offset = read_integer(block, offset, prefix_bits)
        if name_index:
            name = self._field(name_index)[0]
        else:
            name, offset = read_string(block, offset)
        value, offset = read_string(block, offset)
        if indexed:
            self.table.add(name, value)
        return (name, value), offset

    def _resize(self, size):
        """Make a size update from the peer take effect."""
        self.table.max_size = size
        if self.table.size > self.table.max_size:
            self.table.evict_oldest()

# -- Encoding ---------------------------------------------------------------

class Encoder:
    """Turns header lists into header blocks.

    A field that one of the tables already holds is referred to by its index,
    a field whose value must not be kept travels as a literal that is never
    indexed, and everything else joins the dynamic table as it goes out."""

    def __init__(self, max_size=DEFAULT_TABLE_SIZE):
        self.table = DynamicTable(max_size)

    def encode(self, headers):
        """Return the header block that carries headers."""
        out = bytearray()
        for name, value in headers:
            if name in SENSITIVE_NAMES:
                out += self._literal(name, value, 4, 0x10)
                continue
            index = self.index_of(name, value)
            if index is not None:
                out += encode_integer(index, 7, 0x80)
            else:
                out += self._incremental(name, value)
        return bytes(out)

    def index_of(self, name, value):
        """Absolute index of a field the encoder can already point at."""
        for index, entry in enumerate(STATIC_TABLE, 1):
            if entry == (name, value):
                return index
        return None

    def _incremental(self, name, value):
        """Encode a literal that joins the dynamic table."""
        block = self._literal(name, value, 6, 0x40)
        self.table.add(name, value)
        return block

    def _literal(self, name, value, prefix_bits, marker):
        """Encode a literal whose name may come from one of the tables."""
        index = _static_name_index(name)
        if index is None:
            index = self.table.name_index(name)
        block = bytearray(encode_integer(index or 0, prefix_bits, marker))
        if not index:
            block += encode_string(name)
        block += encode_string(value)
        return bytes(block)
