from __future__ import annotations

from ailment import Expr

from angr.engines.vex.claripy.ccall import data
from .rewriter_base import CCallRewriterBase


X86_CondTypes = data["X86"]["CondTypes"]
X86_OpTypes = data["X86"]["OpTypes"]
X86_CondBitMasks = data["X86"]["CondBitMasks"]
X86_CondBitOffsets = data["X86"]["CondBitOffsets"]


class X86CCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for X86.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.callee == "x86g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value
                op_v = op.value
                if cond_v == X86_CondTypes["CondLE"]:  # noqa: SIM102
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <=s dep_2
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            X86_OpTypes["G_CC_OP_SUBB"],
                            X86_OpTypes["G_CC_OP_SUBW"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
        return None

    @staticmethod
    def _fix_size(expr, op_v: int, type_8bit, type_16bit, tags):
        if op_v == type_8bit:
            bits = 8
        elif op_v == type_16bit:
            bits = 16
        else:
            bits = 32
        if bits < 32:
            if isinstance(expr, Expr.Const):
                return Expr.Const(expr.idx, None, expr.value & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(None, 32, bits, False, expr, **tags)
        return expr
