from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import ARMCondHS, ARMCondLE, ARMCondLO, ARMCondMI, ARMCondNE, ARMCondPL
from angr.engines.vex.claripy.ccall import ARMG_CC_OP_SBB, ARMG_CC_OP_SUB

from .rewriter_base import CCallRewriterBase


class ARMCCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for ARM.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.callee == "armg_calculate_condition":
            cond_n_op = ccall.operands[0]

            if isinstance(cond_n_op, Expr.Const):
                concrete_cond_n_op = cond_n_op.value_int
                cond_v = concrete_cond_n_op >> 4
                op_v = concrete_cond_n_op & 0xF
                inv = cond_v & 1

                dep_1 = ccall.operands[1]
                dep_2 = ccall.operands[2]

                if cond_v in {ARMCondHS, ARMCondLO}:
                    # armg_calculate_flag_c
                    if op_v == ARMG_CC_OP_SBB:
                        # dep_1 >= dep_2 if dep_3 == 0 else dep_1 > dep_2,
                        #   and then negate the result if inv == 1
                        dep_3 = ccall.operands[3]
                        if isinstance(dep_3, Expr.Const) and dep_3.value_int == 0:
                            r = Expr.BinaryOp(
                                ccall.idx, "CmpGE" if inv == 0 else "CmpLT", (dep_1, dep_2), False, **ccall.tags
                            )
                        else:
                            r = Expr.BinaryOp(
                                ccall.idx, "CmpGT" if inv == 0 else "CmpLE", (dep_1, dep_2), False, **ccall.tags
                            )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v in {ARMCondMI, ARMCondPL}:
                    # armg_calculate_flag_n
                    if op_v == ARMG_CC_OP_SUB:
                        # dep_1 < dep_2,
                        #   and then negate the result if inv == 1
                        r = Expr.BinaryOp(
                            ccall.idx, "CmpLT" if inv == 0 else "CmpGE", (dep_1, dep_2), False, **ccall.tags
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v in {ARMCondLE}:
                    if op_v == ARMG_CC_OP_SUB:
                        # dep_1 <= dep_2,
                        #   and then negate the result if inv == 1
                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v in {ARMCondNE}:  # noqa: SIM102
                    if op_v == ARMG_CC_OP_SUB:
                        # dep_1 != dep_2,
                        #   and then negate the result if inv == 1
                        r = Expr.BinaryOp(ccall.idx, "CmpNE", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

        return None
