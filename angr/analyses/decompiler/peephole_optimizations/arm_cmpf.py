from __future__ import annotations

from archinfo.arch_arm import is_arm_arch

from angr.ailment.expression import BinaryOp, Const, Convert, Expression, UnaryOp
from angr.analyses.decompiler.x87_fsw import SOURCE_CMPF, evaluate_over_fsw, fsw_predicate
from angr.utils.ail import BlockDefs

from .base import PeepholeOptimizationExprBase

# 1-bit integer operators that test or combine flag bits
_BOOL_OPS = frozenset(
    {"And", "Or", "Xor", "LogicalAnd", "LogicalOr", "CmpEQ", "CmpNE", "CmpLT", "CmpLE", "CmpGT", "CmpGE"}
)
_SOURCE_LOGIC_OPS = frozenset({"And", "Or", "LogicalAnd", "LogicalOr"})


class ARMCmpF(PeepholeOptimizationExprBase):
    """
    Rewrites tests of ARM NZCV flags.

    VEX lowers ``vcmp`` to ``FPSCR = (FPSCR & 0x0fffffff) | nzcv(CmpF(a, b)) << 28`` and ``vmrs APSR_nzcv, fpscr`` to a
    COPY of FPSCR's top nibble into the flags. The condition of the next branch then extracts the flag bits. This
    optimization rewrites the bit test by evaluating each CmpF outcome (seeing through the FPSCR definition in the same
    block, or its unique definition elsewhere in the function) and replacing by the equivalent comparison.
    """

    __slots__ = ("_flag_regs",)

    NAME = "Simplifying CmpF on ARM"
    expr_classes = (Convert, BinaryOp)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._flag_regs: frozenset[int] | None = None

    def _flag_reg_offsets(self) -> frozenset[int]:
        """Offsets of the registers the VFP flags flow through: FPSCR and the VEX condition-code thunk."""
        if self._flag_regs is None:
            assert self.project is not None
            regs = self.project.arch.registers
            self._flag_regs = frozenset(
                regs[name][0] for name in ("fpscr", "cc_op", "cc_dep1", "cc_dep2", "cc_ndep") if name in regs
            )
        return self._flag_regs

    def optimize(
        self,
        expr: Convert | BinaryOp,
        *,
        stmt_idx: int | None = None,  # pylint:disable=unused-argument
        block=None,
        block_defs: BlockDefs | None = None,
        **kwargs,
    ):
        if expr.bits != 1 or self.project is None or not is_arm_arch(self.project.arch):
            return None
        if isinstance(expr, Convert):
            if expr.from_bits == 1 or expr.from_type != Convert.TYPE_INT or expr.to_type != Convert.TYPE_INT:
                return None
        elif expr.op not in _BOOL_OPS or expr.floating_point:
            return None

        defs = BlockDefs.of(block, block_defs)
        # the FPSCR written by vcmp may be read by a vmrs in a later block (and the flags by a branch in yet another);
        # after SSA those register vvars have unique definitions that the whole-graph map sees through
        table = evaluate_over_fsw(
            [expr], defs.vvar_defs(self._flag_reg_offsets()), tmp_defs=defs.tmps, fp_compare_leaves=True
        )
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
