from __future__ import annotations

from angr.ailment.expression import BinaryOp, Const, Tmp, VEXCCallExpression, VirtualVariable
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase

# ID (bit 21), AC (bit 18) and DF (bit 10) of a pushed rflags word
_ID_AC_D_MASKS = frozenset({0x200000, 0x40000, 0x400})


class RemoveIdFlag(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "Remove id, ac and d flags"
    expr_classes = (BinaryOp,)  # all expressions are allowed

    def optimize(self, expr: BinaryOp, *, block=None, block_defs: BlockDefs | None = None, **kwargs):
        # amd64g_calculate_rflags_all(...) | (reg << N & MASK)  =>  amd64g_calculate_rflags_all(...)
        if not (expr.op == "Or" and isinstance(expr.operands[1], BinaryOp) and expr.operands[1].op == "And"):
            return None
        mask = expr.operands[1].operands[1]
        if not (isinstance(mask, Const) and mask.is_int and mask.value_int in _ID_AC_D_MASKS):
            return None
        if self._is_rflags_all(expr.operands[0], block, block_defs):
            return expr.operands[0]
        return None

    @staticmethod
    def _is_rflags_all(expr, block, block_defs: BlockDefs | None) -> bool:
        # the ccall is usually assigned to a tmp (or a vvar after SSA) and only that is Or'ed with the other flags
        if isinstance(expr, (Tmp, VirtualVariable)):
            defs = BlockDefs.of(block, block_defs)
            expr = defs.tmps.get(expr.tmp_idx) if isinstance(expr, Tmp) else defs.vvars.get(expr.varid)
        return isinstance(expr, VEXCCallExpression) and expr.callee == "amd64g_calculate_rflags_all"
