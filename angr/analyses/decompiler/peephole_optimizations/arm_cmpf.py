from __future__ import annotations

from archinfo.arch_arm import is_arm_arch

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, Tmp, UnaryOp, VirtualVariable
from angr.ailment.statement import Assignment
from angr.analyses.decompiler.x87_fsw import SOURCE_CMPF, evaluate_over_fsw, fsw_predicate

from .base import PeepholeOptimizationExprBase

# 1-bit integer operators that test or combine flag bits (e.g. the ccall rewriter's flag tests)
_BOOL_OPS = frozenset(
    {"And", "Or", "Xor", "LogicalAnd", "LogicalOr", "CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}
)
_SOURCE_LOGIC_OPS = frozenset({"And", "Or", "LogicalAnd", "LogicalOr"})


class ARMCmpF(PeepholeOptimizationExprBase):
    """
    Rewrites tests of NZCV flags that a VFP compare derived from a CmpF result into float comparisons.

    VEX lowers ``vcmp`` to ``FPSCR = (FPSCR & 0x0fffffff) | nzcv(CmpF(a, b)) << 28`` and ``vmrs APSR_nzcv, fpscr`` to a
    COPY of FPSCR's top nibble into the flags; the condition of the next branch then extracts flag bits from it. The
    test is evaluated for each CmpF outcome (seeing through the FPSCR definition in the same block) and replaced by the
    equivalent comparison.
    """

    __slots__ = ("_block_cache",)

    NAME = "Simplifying CmpF on ARM"
    expr_classes = (Convert, BinaryOp)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._block_cache: tuple[object, object, dict[int, Expression], dict[int, Expression]] | None = None

    def _block_defs(self, block) -> tuple[dict[int, Expression], dict[int, Expression]]:
        statements = block.statements
        if self._block_cache is not None and self._block_cache[0] is block and self._block_cache[1] is statements:
            return self._block_cache[2], self._block_cache[3]
        vvar_defs: dict[int, Expression] = {}
        tmp_defs: dict[int, Expression] = {}
        for stmt in statements:
            if isinstance(stmt, Assignment):
                if isinstance(stmt.dst, VirtualVariable):
                    vvar_defs[stmt.dst.varid] = stmt.src
                elif isinstance(stmt.dst, Tmp):
                    tmp_defs[stmt.dst.tmp_idx] = stmt.src
        self._block_cache = (block, statements, vvar_defs, tmp_defs)
        return vvar_defs, tmp_defs

    def optimize(self, expr: Convert | BinaryOp, *, stmt_idx: int | None = None, block=None, **kwargs):
        if expr.bits != 1 or self.project is None or not is_arm_arch(self.project.arch):
            return None
        if isinstance(expr, Convert):
            if expr.from_bits == 1 or expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                return None
        elif expr.op not in _BOOL_OPS or expr.floating_point:
            return None

        vvar_defs, tmp_defs = self._block_defs(block) if block is not None else ({}, {})
        table = evaluate_over_fsw([expr], vvar_defs, tmp_defs=tmp_defs, fp_compare_leaves=True)
        if table is None or table.source != SOURCE_CMPF:
            return None
        true_set = table.true_set(lambda vals: vals[0] == 1)
        pred = fsw_predicate(table, true_set, expr.idx, self.manager, 1, expr.tags.copy())
        if pred is not None and self._is_fp_logic(expr):
            # fsw_predicate drops the unordered case like ordered C comparisons do; that is fine for flag arithmetic
            # but must not swallow NaN tests written in the source, e.g. isnan(a) || a < b
            check = evaluate_over_fsw([pred], fp_compare_leaves=True)
            if check is None or check.true_set(lambda vals: vals[0] == 1) != true_set:
                return None
        return pred

    @staticmethod
    def _is_fp_logic(expr: Expression) -> bool:
        """Whether expr only combines float comparisons and NaN tests with logical operators (no flag arithmetic)."""
        if isinstance(expr, BinaryOp):
            if expr.floating_point:
                return expr.op.startswith("Cmp")
            return expr.op in _SOURCE_LOGIC_OPS and all(ARMCmpF._is_fp_logic(o) for o in expr.operands)
        if isinstance(expr, UnaryOp):
            return expr.op == "IsNaN" or (expr.op == "Not" and ARMCmpF._is_fp_logic(expr.operand))
        return isinstance(expr, Const)
