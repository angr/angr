from __future__ import annotations

import struct
from collections.abc import Collection

import archinfo

from angr import ailment
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import DirtyExpression, Expression
from angr.ailment.statement import DirtyStatement, Statement

try:
    from claripy.ast import Bits
except ImportError:
    from typing import Never as Bits

try:
    import _md5 as md5lib  # type: ignore # stdlib C module without stubs
except ImportError:
    import hashlib as md5lib

type GetBitsTypeParams = "ailment.expression.Expression"

_DIRTY_MEMORY_READ_EFFECTS = frozenset({"Ifx_Read", "Ifx_Modify"})
_DIRTY_MEMORY_WRITE_EFFECTS = frozenset({"Ifx_Write", "Ifx_Modify"})


class _EffectfulDirtyExpressionFound(Exception):
    pass


class _EffectfulDirtyExpressionFinder(AILBlockViewer):
    def __init__(self, memory_effects: Collection[str] | None):
        super().__init__()
        self._memory_effects = memory_effects

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_effectful_dirty_expression(expr) and (self._memory_effects is None or expr.mfx in self._memory_effects):
            raise _EffectfulDirtyExpressionFound

        # A DirtyExpression whose own effect does not match may contain another
        # DirtyExpression in an operand, guard, or memory address that does.
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)

    def _handle_DirtyStatement(
        self,
        stmt_idx: int,
        stmt: DirtyStatement,
        block,  # pylint:disable=unused-argument
    ):
        if not is_effectful_dirty_expression(stmt.dirty):
            # A DirtyStatement whose placeholder has mfx=None is the opaque fallback for an unsupported VEX statement.
            # The missing statement semantics may include both memory and non-memory effects.
            raise _EffectfulDirtyExpressionFound

        # VEX IRDirty statements without a result temporary also use DirtyStatement, but retain their known mfx.
        # Recurse so effect queries remain true while memory queries classify Ifx_Read/Write/Modify precisely.
        return super()._handle_DirtyStatement(stmt_idx, stmt, block)


def is_effectful_dirty_expression(expr: Expression) -> bool:
    """
    Return whether ``expr`` directly represents a VEX dirty operation with effects.

    A non-``None`` ``mfx`` marks expressions originating from VEX ``IRDirty``. This includes ``Ifx_None``: it means
    that VEX declares no guest-memory access, not that the helper is pure. Dirty expressions used as placeholders for
    unsupported pure arithmetic have ``mfx=None``.
    """
    return isinstance(expr, DirtyExpression) and expr.mfx is not None


def _contains_effectful_dirty_expression(obj: Expression | Statement, memory_effects: Collection[str] | None) -> bool:
    finder = _EffectfulDirtyExpressionFinder(memory_effects)
    try:
        if isinstance(obj, Expression):
            finder.walk_expression(obj)
        elif isinstance(obj, Statement):
            finder.walk_statement(obj)
        else:
            raise TypeError(type(obj))
    except _EffectfulDirtyExpressionFound:
        return True
    return False


def has_effectful_dirty_expression(obj: Expression | Statement) -> bool:
    """Return whether ``obj`` recursively contains an effectful ``DirtyExpression`` or opaque ``DirtyStatement``."""
    return _contains_effectful_dirty_expression(obj, None)


def has_dirty_memory_read(obj: Expression | Statement) -> bool:
    """Return whether ``obj`` contains a dirty guest-memory read/modification or opaque ``DirtyStatement``."""
    return _contains_effectful_dirty_expression(obj, _DIRTY_MEMORY_READ_EFFECTS)


def has_dirty_memory_write(obj: Expression | Statement) -> bool:
    """Return whether ``obj`` contains a dirty guest-memory write/modification or opaque ``DirtyStatement``."""
    return _contains_effectful_dirty_expression(obj, _DIRTY_MEMORY_WRITE_EFFECTS)


def get_bits(expr: GetBitsTypeParams) -> int:
    if isinstance(expr, ailment.expression.Expression):
        return expr.bits
    if isinstance(expr, Bits):
        return expr.size()
    raise TypeError(type(expr))


md5_unpacker = struct.Struct("4I")


def stable_hash(t: tuple) -> int:
    cnt = _dump_tuple(t)
    hd = md5lib.md5(cnt).digest()
    return md5_unpacker.unpack(hd)[0]  # 32 bits


def _dump_tuple(t: tuple) -> bytes:
    cnt = b""
    for item in t:
        if item is not None:
            type_ = type(item)
            if type_ in _DUMP_BY_TYPE:
                cnt += _DUMP_BY_TYPE[type_](item)
            else:
                # for TaggedObjects, hash(item) is stable
                # other types of items may show up, such as pyvex.expr.CCall and Dirty. they will be removed some day.
                cnt += struct.pack("<Q", hash(item) & 0xFFFF_FFFF_FFFF_FFFF)
        cnt += b"\xf0"
    return cnt


def _dump_str(t: str) -> bytes:
    return t.encode("utf-8")


def _dump_int(t: int) -> bytes:
    prefix = b"" if t >= 0 else b"-"
    t = abs(t)
    if t <= 0xFFFF:
        return prefix + struct.pack("<H", t)
    if t <= 0xFFFF_FFFF:
        return prefix + struct.pack("<I", t)
    if t <= 0xFFFF_FFFF_FFFF_FFFF:
        return prefix + struct.pack("<Q", t)
    cnt = b""
    while t > 0:
        cnt += _dump_int(t & 0xFFFF_FFFF_FFFF_FFFF)
        t >>= 64
    return prefix + cnt


def _dump_type(t: type) -> bytes:
    return t.__name__.encode("ascii")


_DUMP_BY_TYPE = {
    tuple: _dump_tuple,
    str: _dump_str,
    int: _dump_int,
    type: _dump_type,
}


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


def is_lsb_extract(expr: ailment.expression.Expression) -> bool:
    """
    Return ``True`` if ``expr`` is an ``Extract`` that takes the least-significant ``expr.bits`` bits of its base,
    considering endianness.
    """
    if not isinstance(expr, ailment.expression.Extract):
        return False
    if not isinstance(expr.offset, ailment.expression.Const):
        return False
    if expr.endness == archinfo.Endness.LE:
        return expr.offset.value == 0
    return expr.offset.value * 8 + expr.bits == expr.base.bits


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
    if expr.endness == archinfo.Endness.LE:
        return expr.offset.value == 0
    return expr.offset.value * 8 + expr.value.bits == expr.bits
