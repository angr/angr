"""Decoder for the ``core::fmt::Arguments`` template byte encoding introduced in rustc 1.93.

See the comment on ``struct Arguments`` in library/core/src/fmt/mod.rs.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

SIGN_PLUS_FLAG = 1 << 21
SIGN_MINUS_FLAG = 1 << 22
ALTERNATE_FLAG = 1 << 23
SIGN_AWARE_ZERO_PAD_FLAG = 1 << 24
DEBUG_LOWER_HEX_FLAG = 1 << 25
DEBUG_UPPER_HEX_FLAG = 1 << 26
WIDTH_FLAG = 1 << 27
PRECISION_FLAG = 1 << 28
DEFAULT_FLAGS = 0x6000_0020

MAX_TEMPLATE_SIZE = 0x10000 * 4


@dataclass
class Placeholder:
    """One ``{...}`` in a format template."""

    arg_index: int
    flags: int = DEFAULT_FLAGS
    width: int | None = None
    precision: int | None = None
    width_indirect: bool = False
    precision_indirect: bool = False

    def spec(self, trait: str) -> str:
        """Render the part after ``:`` (without the ``:``). ``trait`` is "", "?", "x", "X", "o", "b", "e", "E", "p"."""
        flags = self.flags
        s = ""
        align = (flags >> 29) & 3
        if align != 3:
            fill = chr(flags & 0x1FFFFF)
            if fill != " ":
                s += fill
            s += "<>^"[align]
        if flags & SIGN_PLUS_FLAG:
            s += "+"
        if flags & SIGN_MINUS_FLAG:
            s += "-"
        if flags & ALTERNATE_FLAG:
            s += "#"
        if flags & SIGN_AWARE_ZERO_PAD_FLAG:
            s += "0"
        if self.width is not None:
            s += f"{self.width}$" if self.width_indirect else str(self.width)
        if self.precision is not None:
            s += "." + (f"{self.precision}$" if self.precision_indirect else str(self.precision))
        if trait == "?" and flags & DEBUG_LOWER_HEX_FLAG:
            s += "x?"
        elif trait == "?" and flags & DEBUG_UPPER_HEX_FLAG:
            s += "X?"
        else:
            s += trait
        return s


def decode_template(read: Callable[[int, int], bytes | None], addr: int) -> list[str | Placeholder] | None:
    """
    Decode a template at ``addr``. ``read(addr, size)`` returns the bytes or None when unreadable.
    Returns the list of literal pieces and placeholders, or None if the bytes are not a valid template.
    """
    pieces: list[str | Placeholder] = []
    next_arg = 0
    pos = addr
    end = addr + MAX_TEMPLATE_SIZE

    def _take(size: int) -> bytes | None:
        nonlocal pos
        data = read(pos, size)
        if data is None or len(data) != size:
            return None
        pos += size
        return data

    def _u16() -> int | None:
        data = _take(2)
        return None if data is None else int.from_bytes(data, "little")

    while pos < end:
        head = _take(1)
        if head is None:
            return None
        n = head[0]
        if n == 0:
            return pieces
        if n <= 0x80:
            if n == 0x80:
                length = _u16()
                if length is None:
                    return None
            else:
                length = n
            data = _take(length)
            if data is None:
                return None
            try:
                pieces.append(data.decode("utf-8"))
            except UnicodeDecodeError:
                return None
            continue
        if n < 0xC0:
            return None
        ph = Placeholder(arg_index=next_arg)
        if n & 1:
            data = _take(4)
            if data is None:
                return None
            ph.flags = int.from_bytes(data, "little")
        if n & 2:
            ph.width = _u16()
            if ph.width is None:
                return None
        elif ph.flags & WIDTH_FLAG:
            ph.width = 0
        if n & 4:
            ph.precision = _u16()
            if ph.precision is None:
                return None
        elif ph.flags & PRECISION_FLAG:
            ph.precision = 0
        if n & 8:
            idx = _u16()
            if idx is None:
                return None
            ph.arg_index = idx
        ph.width_indirect = bool(n & 16)
        ph.precision_indirect = bool(n & 32)
        if (ph.width_indirect and ph.width is None) or (ph.precision_indirect and ph.precision is None):
            return None
        next_arg = ph.arg_index + 1
        pieces.append(ph)
    return None


def num_args(pieces: list[str | Placeholder]) -> int:
    """The number of ``rt::Argument`` entries a template refers to."""
    n = 0
    for p in pieces:
        if isinstance(p, Placeholder):
            n = max(n, p.arg_index + 1)
            if p.width_indirect and p.width is not None:
                n = max(n, p.width + 1)
            if p.precision_indirect and p.precision is not None:
                n = max(n, p.precision + 1)
    return n
