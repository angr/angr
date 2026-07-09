from __future__ import annotations

DEFAULT_STATEMENT = -2
SWITCH_MISSING_DEFAULT_NODE_ADDR = 0xFFFF_FFFE
MAX_POINTSTO_BITS = -1330 * 8

#: Well-known "magic" constants that are universally recognized in hexadecimal.
MAGIC_CONSTANTS = frozenset(
    {
        0xDEADBEEF,
        0xDEADC0DE,
        0xDEADBABE,
        0xDEADDEAD,
        0xCAFEBABE,
        0xCAFED00D,
        0xBAADF00D,
        0x0BADF00D,
        0x8BADF00D,
        0xFEEDFACE,
        0xFACEFEED,
        0xFEE1DEAD,
        0xBADDCAFE,
        0xABADBABE,
    }
)


def is_alignment_mask(n):
    return n in {0xFFFFFFFFFFFFFFE0, 0xFFFFFFFFFFFFFFF0, 0xFFFFFFC0, 0xFFFFFFE0, 0xFFFFFFF0, 0xFFFFFFFC, 0xFFFFFFF8}


def _max_consecutive_run(s: str, ch: str) -> int:
    """Return the length of the longest run of ``ch`` in ``s``."""
    best = cur = 0
    for c in s:
        if c == ch:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def _has_repeated_bit_pattern(bitstr: str) -> bool:
    """
    Return whether ``bitstr`` (a byte-aligned binary string) is a short bit pattern repeated to fill its width, e.g.
    ``"01010101"`` (0x55), ``"0001000100010001"`` (0x1111), or ``"10101011..."`` (0xABAB). Periods of 1 (all-ones)
    are intentionally excluded here -- those are handled by the consecutive-ones rule.
    """
    n = len(bitstr)
    if n < 8:
        return False
    for period in (2, 3, 4, 8):
        if period >= n or n % period != 0:
            continue
        block = bitstr[:period]
        # require a non-trivial block (a mix of 0s and 1s) repeated to fill the whole width
        if "0" in block and "1" in block and block * (n // period) == bitstr:
            return True
    return False


def should_use_hex(value: int, bits: int | None = None) -> bool:
    """
    Heuristically decide whether an integer constant reads better in hexadecimal than in decimal in decompiled output.

    The rules are checked in priority order:

    Hexadecimal (returns ``True``):

    0. Small negative values (``-255 <= value < 0``) are always shown in decimal.
    1. The value is a well-known "magic" constant (e.g. ``0xdeadbeef``); see :data:`MAGIC_CONSTANTS`.
    2. The value is a known alignment mask; see :func:`is_alignment_mask`.
    3. The binary representation contains a run of **>= 8** consecutive ``1`` bits -- typical of sub-word bitmasks
       (e.g. ``0xff``, ``0xfff``).
    4. The binary representation is a short bit pattern (period 2, 3, 4, or 8) repeated to fill a byte-aligned width
       -- typical of mask/flag constants (e.g. ``0x55``/``0xaaaa`` for ``0101...``, ``0x1111``, ``0xabab``).
    5. The value is a single set bit (power of two) that is **>= 256** -- a bit flag (e.g. ``0x100``, ``0x4000``).

    Decimal (returns ``False``):

    6. The decimal representation of ``abs(value)`` contains a run of **> 3** (i.e. >= 4) identical digits
       (e.g. ``10000``, ``11111``, ``1000000``).
    7. The value is a nonzero multiple of 1000 -- a "round" human-authored decimal number (e.g. ``5000``, ``20000``).
    8. The magnitude is small (``abs(value) <= 9``) -- e.g. small loop counters and offsets.

    Hexadecimal (weak signal, returns ``True``):

    9. The low byte is zero and the value is ``> 0xff`` -- a "round" hex number (e.g. ``0x1200``).

    10. The value is a common error code (e.g. ``0xc0000005``) in a 32- or 64-bit context.

    Otherwise the value is shown in decimal (returns ``False``).

    :param value:   The integer value to format.
    :param bits:    The bit-width of the value's type. Used to normalize negative values to their unsigned form. If
                    ``None``, the value's own bit length is used.
    :return:        ``True`` if the value should be displayed in hexadecimal, ``False`` for decimal.
    """

    # normalize to an unsigned representation for bit-level inspection
    if value < 0:
        if value >= -255:
            # 0. small negative values are always displayed as decimal
            return False
        width = bits or max(8, (value.bit_length() + 8) // 8 * 8)
        u = value & ((1 << width) - 1)
    else:
        u = value

    # 1. magic constants
    if u in MAGIC_CONSTANTS:
        return True

    # 2. alignment masks
    if is_alignment_mask(u):
        return True

    # byte-aligned binary string (no dependence on the declared container width)
    byte_width = max(8, (u.bit_length() + 7) // 8 * 8)
    bitstr = format(u, f"0{byte_width}b")

    # 3. long run of consecutive 1 bits (sub-word bitmasks such as 0xff, 0xfff)
    if _max_consecutive_run(bitstr, "1") >= 8:
        return True

    # 4. repeated bit-level pattern
    if _has_repeated_bit_pattern(bitstr):
        return True

    # 5. single-bit flags (powers of two) at or above 0x100
    if u >= 0x100 and (u & (u - 1)) == 0:
        return True

    # 6. long run of identical decimal digits
    decstr = str(abs(value))
    if any(_max_consecutive_run(decstr, d) >= 4 for d in "0123456789"):
        return False

    # 7. round decimal numbers
    if value != 0 and value % 1000 == 0:
        return False

    # 8. small magnitudes
    if abs(value) <= 9:
        return False

    # 9. round hex numbers (low byte zero)
    if u > 0xFF and (u & 0xFF) == 0:
        return True

    # 10. common error codes
    return bits in {32, 64} and (u & 0xFFFF0000) in {0xC0000000, 0x80000000}
