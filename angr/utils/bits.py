from __future__ import annotations


def truncate_bits(value: int, nbits: int) -> int:
    """
    Truncate `value` to `nbits`.

    For example: truncate_bits(0x1234, 8) -> 0x34
    """
    if nbits < 0:
        raise ValueError("nbits must not be negative")
    return value & (2**nbits - 1)
