from __future__ import annotations

import archinfo

from angr import ailment
from angr.ailment.block_walker import AILBlockViewer
from angr.ailment.expression import DirtyExpression, Expression
from angr.ailment.statement import Statement

try:
    from claripy.ast import Bits
except ImportError:
    from typing import Never as Bits

type GetBitsTypeParams = "ailment.expression.Expression"

_LOAD_LINKED_CALLEES = frozenset({"load_linked_le", "load_linked_be", "load_linked_unknown_endness"})
_STORE_CONDITIONAL_CALLEES = frozenset(
    {"store_conditional_le", "store_conditional_be", "store_conditional_unknown_endness"}
)


def is_llsc_expression(expr: Expression) -> bool:
    """Return whether ``expr`` is an LL/SC operation emitted by the VEX-to-AIL converter."""
    return isinstance(expr, DirtyExpression) and (
        (expr.callee in _LOAD_LINKED_CALLEES and expr.mfx == "Ifx_Read")
        or (expr.callee in _STORE_CONDITIONAL_CALLEES and expr.mfx == "Ifx_Write")
    )


def is_store_conditional_expression(expr: Expression) -> bool:
    """Return whether ``expr`` is a store-conditional emitted by the VEX-to-AIL converter."""
    return isinstance(expr, DirtyExpression) and expr.callee in _STORE_CONDITIONAL_CALLEES and expr.mfx == "Ifx_Write"


class _LLSCExpressionFound(Exception):
    pass


class _LLSCExpressionFinder(AILBlockViewer):
    def __init__(self, store_conditional_only: bool):
        super().__init__()
        self._store_conditional_only = store_conditional_only

    def _handle_DirtyExpression(self, expr_idx, expr, stmt_idx, stmt, block):
        if is_store_conditional_expression(expr) if self._store_conditional_only else is_llsc_expression(expr):
            raise _LLSCExpressionFound
        return super()._handle_DirtyExpression(expr_idx, expr, stmt_idx, stmt, block)


def _contains_llsc_expression(obj: Expression | Statement, store_conditional_only: bool) -> bool:
    if isinstance(obj, DirtyExpression):
        return is_store_conditional_expression(obj) if store_conditional_only else is_llsc_expression(obj)

    finder = _LLSCExpressionFinder(store_conditional_only)
    try:
        if isinstance(obj, Expression):
            finder.walk_expression(obj)
        elif isinstance(obj, Statement):
            finder.walk_statement(obj)
        else:
            raise TypeError(type(obj))
    except _LLSCExpressionFound:
        return True
    return False


def has_llsc_expression(obj: Expression | Statement) -> bool:
    """Return whether ``obj`` recursively contains a converted LL/SC operation."""
    return _contains_llsc_expression(obj, False)


def has_store_conditional(obj: Expression | Statement) -> bool:
    """Return whether ``obj`` recursively contains a converted store-conditional operation."""
    return _contains_llsc_expression(obj, True)


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
