from __future__ import annotations

import math

from angr.ailment.expression import ITE, BinaryOp, Const, Register, VirtualVariable
from angr.ailment.statement import Assignment

from .base import PeepholeOptimizationExprBase


class RemoveFptagNanITE(PeepholeOptimizationExprBase):
    """
    VEX x87 lifting wraps FP register accesses in fptag validity checks:
      ITE(fptag != 0, fp_value, empty)   -- for reads (valid -> value, empty -> NaN/0 placeholder)
      ITE(fptag != 0, empty, fp_value)   -- for pushes

    Since decompiled code assumes FP registers are valid, strip these ITEs and keep the
    real (non-placeholder) branch. The placeholder is a NaN constant, or -- before later
    simplification turns it into a NaN -- a zero constant guarded by a condition that reads
    the x87 fptag register.
    """

    __slots__ = ()

    NAME = "Remove fptag NaN ITE checks"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, *, block=None, **kwargs):
        iftrue_is_nan = _is_nan(expr.iftrue)
        iffalse_is_nan = _is_nan(expr.iffalse)

        # Classic form: one (or both) branches are already a NaN constant.
        if iftrue_is_nan and not iffalse_is_nan:
            return expr.iffalse
        if iffalse_is_nan and not iftrue_is_nan:
            return expr.iftrue
        if iftrue_is_nan and iffalse_is_nan:
            return expr.iftrue

        # Pre-NaN form: the condition reads the fptag register and exactly one branch is a
        # zero-constant placeholder. Keep the real branch.
        if self.project is not None and self._cond_reads_fptag(expr.cond, block):
            iftrue_zero = _is_zero(expr.iftrue)
            iffalse_zero = _is_zero(expr.iffalse)
            if iftrue_zero and not iffalse_zero:
                return expr.iffalse
            if iffalse_zero and not iftrue_zero:
                return expr.iftrue

        return None

    def _cond_reads_fptag(self, cond, block) -> bool:
        assert self.project is not None
        fptag = self.project.arch.registers.get("fptag")
        if fptag is None:
            return False
        lo, hi = fptag[0], fptag[0] + fptag[1]

        vvar_defs: dict[int, object] = {}
        if block is not None:
            for stmt in block.statements:
                if isinstance(stmt, Assignment) and isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src

        def reads(e, depth=4):
            while depth > 0 and isinstance(e, VirtualVariable) and e.varid in vvar_defs:
                e = vvar_defs[e.varid]
                depth -= 1
            if isinstance(e, VirtualVariable) and e.was_reg and lo <= e.reg_offset < hi:
                return True
            if isinstance(e, Register) and lo <= e.reg_offset < hi:
                return True
            if isinstance(e, BinaryOp) and e.op.startswith("Cmp"):
                return any(reads(op, depth - 1) for op in e.operands)
            return False

        return reads(cond)


def _is_nan(e) -> bool:
    return isinstance(e, Const) and isinstance(e.value, float) and math.isnan(e.value)


def _is_zero(e) -> bool:
    return isinstance(e, Const) and isinstance(e.value, int) and e.value == 0
