from __future__ import annotations

import archinfo

from angr import ailment

try:
    from claripy.ast import Bits
except ImportError:
    from typing import Never as Bits

type GetBitsTypeParams = "ailment.expression.Expression"


def get_bits(expr: GetBitsTypeParams) -> int:
    if isinstance(expr, ailment.expression.Expression):
        return expr.bits
    if isinstance(expr, Bits):
        return expr.size()
    raise TypeError(type(expr))


def is_none_or_likeable(arg1, arg2, is_list=False):
    """
    Returns whether two things are both None or can like each other
    """
    if arg1 is None or arg2 is None:
        return arg1 == arg2

    if is_list:
        return len(arg1) == len(arg2) and all(is_none_or_likeable(a1, a2) for a1, a2 in zip(arg1, arg2))

    if isinstance(arg1, ailment.expression.Expression):
        return arg1.likes(arg2)
    return arg1 == arg2


def is_none_or_matchable(arg1, arg2, is_list=False):
    """
    Returns whether two things are both None or can match each other
    """
    if arg1 is None or arg2 is None:
        return arg1 == arg2

    if is_list:
        return len(arg1) == len(arg2) and all(is_none_or_matchable(a1, a2) for a1, a2 in zip(arg1, arg2))

    if isinstance(arg1, ailment.expression.Expression):
        return arg1.matches(arg2)
    return arg1 == arg2


def lsb_bit_offset(base_bits: int, field_bits: int, byte_offset: int, endness: str, byte_width: int = 8) -> int:
    """
    Return where the low end of a field sits inside its base, counted in bits up from the low end of the base.

    ``Extract`` and ``Insert`` count ``offset`` in bytes from the start of the base in memory order, so on a
    big-endian value byte 0 holds the most significant bits and the field's low end is at the far side of the base.
    """
    if endness == archinfo.Endness.LE:
        return byte_offset * byte_width
    return base_bits - byte_offset * byte_width - field_bits


def is_lsb_extract(expr: ailment.expression.Expression) -> bool:
    """
    Return ``True`` if ``expr`` is an ``Extract`` that takes the least-significant ``expr.bits`` bits of its base,
    considering endianness.
    """
    if not isinstance(expr, ailment.expression.Extract):
        return False
    if not isinstance(expr.offset, ailment.expression.Const):
        return False
    return lsb_bit_offset(expr.base.bits, expr.bits, expr.offset.value, expr.endness) == 0


def is_lsb_overwrite(expr: ailment.expression.Expression) -> bool:
    """
    Return ``True`` if ``expr`` is an ``Insert`` that overwrites the least-significant ``expr.value.bits`` bits of its
    base, considering endianness.

    ``Insert`` counterpart of ``is_lsb_extract``.
    """
    if not isinstance(expr, ailment.expression.Insert):
        return False
    if not (isinstance(expr.offset, ailment.expression.Const) and isinstance(expr.offset.value, int)):
        return False
    return lsb_bit_offset(expr.bits, expr.value.bits, expr.offset.value, expr.endness) == 0
