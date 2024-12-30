from __future__ import annotations

import claripy


def truncate_bits(value: int, nbits: int) -> int:
    """
    Truncate `value` to `nbits`.

    For example: truncate_bits(0x1234, 8) -> 0x34
    """
    if nbits < 0:
        raise ValueError("nbits must not be negative")
    return value & (2**nbits - 1)


def ffs(x: int) -> int:
    return (x & -x).bit_length() - 1


def sign_extend(value: int, bits: int) -> int:
    sign_bit = 1 << (bits - 1)
    return (value & (sign_bit - 1)) - (value & sign_bit)


def zeroextend_on_demand(op0: claripy.ast.BV, op1: claripy.ast.BV) -> claripy.ast.BV:
    """
    ZeroExtend op1 if the size of op1 is smaller than the size of op0. Otherwise, return op1.
    """

    if op0.size() > op1.size():
        return claripy.ZeroExt(op0.size() - op1.size(), op1)
    return op1


def s2u(s, bits):
    mask = (1 << bits) - 1
    if s > 0:
        return s & mask
    return ((1 << bits) + s) & mask


def u2s(u, bits):
    if u < (1 << (bits - 1)):
        return u
    return (u & ((1 << bits) - 1)) - (1 << bits)
