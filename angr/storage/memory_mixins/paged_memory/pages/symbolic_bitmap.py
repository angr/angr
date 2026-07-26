from __future__ import annotations

# Expansion table: a byte value -> eight bytes, one per bit, least-significant bit first. Used to turn a slice of the
# packed representation back into the one-byte-per-byte form that the native interfaces expect.
_EXPAND: tuple[bytes, ...] = tuple(bytes((v >> i) & 1 for i in range(8)) for v in range(256))


class SymbolicBitmap:
    """
    Tracks, for every byte of an :class:`UltraPage`, whether that byte is symbolic.

    The map is stored as a real bitmap -- one *bit* per byte of the page, so a 4096-byte page needs 512 bytes instead
    of the 4096 bytes that a byte-per-byte map would need. Bit ``i`` of the map lives in bit ``i & 7`` of byte
    ``i >> 3`` (least-significant bit first), which makes ``int.from_bytes(..., "little")`` a direct view of the map as
    a big integer and lets range scans be done with ``bit_length()`` instead of a Python-level loop.

    On top of that, a page whose map is *uniform* -- every byte symbolic, or every byte concrete -- stores no per-byte
    metadata at all: ``_bits`` is ``None`` and ``_uniform`` holds the single value. The backing store is only
    materialized when a write actually makes the page non-uniform, and a range write that covers the whole page drops
    back to the uniform representation. Freshly created pages are uniform, so in practice most pages never allocate.

    All ranges are half-open ``[start, stop)`` and are assumed to lie within ``[0, size]``.
    """

    __slots__ = ("_bits", "_uniform", "size")

    def __init__(self, size: int, value: int = 0):
        self.size = size
        self._bits: bytearray | None = None
        self._uniform: int = 1 if value else 0

    #
    # Introspection
    #

    @property
    def nbytes(self) -> int:
        """
        The number of bytes of backing store this map currently occupies (0 while uniform).
        """
        return 0 if self._bits is None else len(self._bits)

    def uniform_value(self) -> int | None:
        """
        Return 0/1 if every byte of the page has that symbolic-ness, or None if the map is mixed.
        """
        return self._uniform if self._bits is None else None

    def _materialize(self) -> bytearray:
        n = (self.size + 7) >> 3
        bits = bytearray(b"\xff" * n) if self._uniform else bytearray(n)
        self._bits = bits
        return bits

    #
    # Scalar access
    #

    def get(self, i: int) -> int:
        """
        Return 1 if byte ``i`` is symbolic, 0 otherwise.
        """
        bits = self._bits
        if bits is None:
            return self._uniform
        return (bits[i >> 3] >> (i & 7)) & 1

    def set(self, i: int, value: int) -> None:
        """
        Mark byte ``i`` as symbolic (``value`` truthy) or concrete.
        """
        bits = self._bits
        if bits is None:
            if bool(value) == bool(self._uniform):
                return
            bits = self._materialize()
        if value:
            bits[i >> 3] |= 1 << (i & 7)
        else:
            bits[i >> 3] &= ~(1 << (i & 7)) & 0xFF

    #
    # Range writes
    #

    def set_range(self, start: int, stop: int) -> None:
        """
        Mark ``[start, stop)`` as symbolic.
        """
        if start >= stop:
            return
        bits = self._bits
        if start <= 0 and stop >= self.size:
            # the whole page: collapse to the uniform representation and drop the backing store
            self._bits = None
            self._uniform = 1
            return
        if bits is None:
            if self._uniform:
                return
            bits = self._materialize()

        fb, fo = start >> 3, start & 7
        lb, lo = stop >> 3, stop & 7
        if fb == lb:
            bits[fb] |= (0xFF << fo) & (0xFF >> (8 - lo)) & 0xFF
            return
        if fo:
            bits[fb] |= (0xFF << fo) & 0xFF
            fb += 1
        if fb < lb:
            bits[fb:lb] = b"\xff" * (lb - fb)
        if lo:
            bits[lb] |= 0xFF >> (8 - lo)

    def clear_range(self, start: int, stop: int) -> None:
        """
        Mark ``[start, stop)`` as concrete.
        """
        if start >= stop:
            return
        bits = self._bits
        if start <= 0 and stop >= self.size:
            self._bits = None
            self._uniform = 0
            return
        if bits is None:
            if not self._uniform:
                return
            bits = self._materialize()

        fb, fo = start >> 3, start & 7
        lb, lo = stop >> 3, stop & 7
        if fb == lb:
            bits[fb] &= ~((0xFF << fo) & (0xFF >> (8 - lo))) & 0xFF
            return
        if fo:
            bits[fb] &= ~(0xFF << fo) & 0xFF
            fb += 1
        if fb < lb:
            bits[fb:lb] = bytes(lb - fb)
        if lo:
            bits[lb] &= ~(0xFF >> (8 - lo)) & 0xFF

    #
    # Range scans
    #

    def next_set(self, start: int, stop: int) -> int:
        """
        Return the smallest ``i`` in ``[start, stop)`` whose byte is symbolic, or ``stop`` if there is none.

        A whole range is turned into one big integer and located with ``(w & -w).bit_length()`` rather than being
        walked bit by bit. Long ranges are probed 64 bits at a time first, so that a hit near ``start`` -- the usual
        case -- does not pay for converting the rest of the page.
        """
        if start >= stop:
            return stop
        bits = self._bits
        if bits is None:
            return start if self._uniform else stop
        pos = start
        window = 64
        while pos < stop:
            end = pos + window
            if end > stop:
                end = stop
            n = end - pos
            fb = pos >> 3
            off = pos & 7
            if fb == (end - 1) >> 3:
                w = (bits[fb] >> off) & ((1 << n) - 1)
            else:
                w = (int.from_bytes(bits[fb : (end + 7) >> 3], "little") >> off) & ((1 << n) - 1)
            if w:
                return pos + (w & -w).bit_length() - 1
            pos = end
            window = stop  # after the initial probe, do the remainder in one shot
        return stop

    def next_clear(self, start: int, stop: int) -> int:
        """
        Return the smallest ``i`` in ``[start, stop)`` whose byte is concrete, or ``stop`` if there is none.
        """
        if start >= stop:
            return stop
        bits = self._bits
        if bits is None:
            return stop if self._uniform else start
        pos = start
        window = 64
        while pos < stop:
            end = pos + window
            if end > stop:
                end = stop
            n = end - pos
            fb = pos >> 3
            off = pos & 7
            if fb == (end - 1) >> 3:
                w = (~bits[fb] >> off) & ((1 << n) - 1)
            else:
                w = (~int.from_bytes(bits[fb : (end + 7) >> 3], "little") >> off) & ((1 << n) - 1)
            if w:
                return pos + (w & -w).bit_length() - 1
            pos = end
            window = stop
        return stop

    def all_set(self, start: int, stop: int) -> bool:
        """
        Return True if every byte in ``[start, stop)`` is symbolic.
        """
        if start >= stop:
            return True
        if self._bits is None:
            return bool(self._uniform)
        return self.next_clear(start, stop) == stop

    def any_set(self, start: int, stop: int) -> bool:
        """
        Return True if any byte in ``[start, stop)`` is symbolic.
        """
        return self.next_set(start, stop) != stop

    #
    # Conversion
    #

    def to_bytemap(self, start: int, stop: int) -> bytes:
        """
        Return ``[start, stop)`` expanded to one byte per byte of the page -- the representation the native unicorn
        and icicle interfaces consume.
        """
        n = stop - start
        if n <= 0:
            return b""
        bits = self._bits
        if bits is None:
            return (b"\x01" if self._uniform else b"\x00") * n
        off = start & 7
        raw = bits[start >> 3 : (stop + 7) >> 3]
        return b"".join([_EXPAND[c] for c in raw])[off : off + n]

    def expanded(self) -> ByteSymbolicBitmap:
        """
        Return a byte-per-byte map with the same contents. Used when a caller needs a *writable* buffer aliasing this
        page (native unicorn's direct page mapping writes taint values back through it).
        """
        return ByteSymbolicBitmap(self.size, bytearray(self.to_bytemap(0, self.size)))

    def copy(self) -> SymbolicBitmap:
        o = SymbolicBitmap.__new__(SymbolicBitmap)
        o.size = self.size
        bits = self._bits
        o._bits = None if bits is None else bytearray(bits)
        o._uniform = self._uniform
        return o


class ByteSymbolicBitmap:
    """
    The legacy one-byte-per-byte representation of :class:`SymbolicBitmap`.

    A page only switches to this representation when something asks for a writable buffer that aliases the page's map
    -- in practice only native unicorn's direct page mapping, which writes ``taint_t`` values (including
    ``TAINT_DIRTY``, which does not fit in one bit) straight into it. Everything else uses the packed representation.
    """

    __slots__ = ("_bytes", "size")

    def __init__(self, size: int, data: bytearray | None = None):
        self.size = size
        self._bytes = bytearray(size) if data is None else data

    @property
    def nbytes(self) -> int:
        return len(self._bytes)

    def uniform_value(self) -> int | None:
        b = self._bytes
        if not b:
            return None
        first = 1 if b[0] else 0
        for v in b:
            if bool(v) != bool(first):
                return None
        return first

    def get(self, i: int) -> int:
        return self._bytes[i]

    def set(self, i: int, value: int) -> None:
        self._bytes[i] = value

    def set_range(self, start: int, stop: int) -> None:
        if start < stop:
            self._bytes[start:stop] = b"\1" * (stop - start)

    def clear_range(self, start: int, stop: int) -> None:
        if start < stop:
            self._bytes[start:stop] = bytes(stop - start)

    def next_set(self, start: int, stop: int) -> int:
        b = self._bytes
        i = start
        while i < stop and not b[i]:
            i += 1
        return i

    def next_clear(self, start: int, stop: int) -> int:
        b = self._bytes
        i = start
        while i < stop and b[i]:
            i += 1
        return i

    def all_set(self, start: int, stop: int) -> bool:
        return self.next_clear(start, stop) == stop

    def any_set(self, start: int, stop: int) -> bool:
        return self.next_set(start, stop) != stop

    def to_bytemap(self, start: int, stop: int) -> bytes:
        return bytes(self._bytes[start:stop])

    def writable_view(self, start: int, stop: int) -> memoryview:
        return memoryview(self._bytes)[start:stop]

    def expanded(self) -> ByteSymbolicBitmap:
        return self

    def copy(self) -> ByteSymbolicBitmap:
        return ByteSymbolicBitmap(self.size, bytearray(self._bytes))


__all__ = ("ByteSymbolicBitmap", "SymbolicBitmap")
