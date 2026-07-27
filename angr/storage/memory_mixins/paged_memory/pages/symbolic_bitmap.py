from __future__ import annotations


class SymbolicBitmap:
    """
    Tracks, for every byte of an :class:`UltraPage`, whether that byte is symbolic.

    The map is stored as a real bitmap -- one *bit* per byte of the page, so a 4096-byte page needs 512 bytes instead
    of the 4096 bytes that a byte-per-byte map would need. Bit ``i`` of the map lives in bit ``i & 7`` of byte
    ``i >> 3`` (least-significant bit first), which makes ``int.from_bytes(..., "little")`` a direct view of the map as
    a big integer and lets range scans be done with ``bit_length()`` instead of a Python-level loop. This is also the
    layout the native interfaces consume, so :meth:`view` can hand them the backing store as-is.

    On top of that, a page whose map is *uniform* -- every byte symbolic, or every byte concrete -- stores no per-byte
    metadata at all: ``_bits`` is ``None`` and ``_uniform`` holds the single value. The backing store is only
    materialized when a write actually makes the page non-uniform, and a range write that covers the whole page drops
    back to the uniform representation. Freshly created pages are uniform, so in practice most pages never allocate.

    All ranges are half-open ``[start, stop)`` and are assumed to lie within ``[0, size]``.
    """

    __slots__ = ("_bits", "_pinned", "_uniform", "size")

    def __init__(self, size: int, value: int = 0):
        self.size = size
        self._bits: bytearray | None = None
        self._uniform: int = 1 if value else 0
        # set once :meth:`view` hands out an aliasing buffer; see there for why the backing store may not be dropped
        # afterwards
        self._pinned: bool = False

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
            # the whole page: collapse to the uniform representation and drop the backing store, unless someone is
            # holding a pointer into it, in which case fill it in place
            if self._pinned:
                assert bits is not None
                bits[:] = b"\xff" * len(bits)
            else:
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
            if self._pinned:
                assert bits is not None
                bits[:] = bytes(len(bits))
            else:
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
    # Buffer access
    #

    def view(self, start: int, stop: int) -> memoryview:
        """
        Return the packed bits covering ``[start, stop)``: bit ``i`` of the result is byte ``start + i`` of the page.

        When ``start`` is byte-aligned the result is a *writable* view of this map's own backing store, so a native
        consumer can update the page's symbolic-ness in place -- native unicorn maps whole pages this way and writes
        taint straight back through the view. Handing out such a view pins the backing store: it may no longer be
        dropped in favor of the uniform representation while someone might still hold a pointer into it.

        An unaligned ``start`` cannot be expressed as a view of the backing store, so the bits are shifted into place
        and returned read-only.
        """
        if start & 7:
            return memoryview(self._shifted(start, stop))
        bits = self._bits
        if bits is None:
            bits = self._materialize()
        self._pinned = True
        return memoryview(bits)[start >> 3 : (stop + 7) >> 3]

    def _shifted(self, start: int, stop: int) -> bytes:
        n = stop - start
        if n <= 0:
            return b""
        bits = self._bits
        if bits is None:
            w = ((1 << n) - 1) if self._uniform else 0
        else:
            w = (int.from_bytes(bits[start >> 3 : (stop + 7) >> 3], "little") >> (start & 7)) & ((1 << n) - 1)
        return w.to_bytes((n + 7) >> 3, "little")

    def copy(self) -> SymbolicBitmap:
        o = SymbolicBitmap.__new__(SymbolicBitmap)
        o.size = self.size
        bits = self._bits
        o._bits = None if bits is None else bytearray(bits)
        o._uniform = self._uniform
        # the copy is a fresh buffer that nobody holds a pointer into
        o._pinned = False
        return o


__all__ = ("SymbolicBitmap",)
