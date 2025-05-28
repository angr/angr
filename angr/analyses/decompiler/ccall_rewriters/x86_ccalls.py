from __future__ import annotations

from angr.ailment import Expr

from angr.engines.vex.claripy.ccall import data
from .rewriter_base import CCallRewriterBase


X86_CondTypes = data["X86"]["CondTypes"]
X86_OpTypes = data["X86"]["OpTypes"]
X86_CondBitMasks = data["X86"]["CondBitMasks"]
X86_CondBitOffsets = data["X86"]["CondBitOffsets"]


class X86CCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for X86.

    From libVEX:

    A summary of the field usages is:

    Operation          DEP1               DEP2               NDEP
    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    add/sub/mul        first arg          second arg         unused
    adc/sbb            first arg          (second arg)
                                          XOR old_carry      old_carry
    and/or/xor         result             zero               unused
    inc/dec            result             zero               old_carry
    shl/shr/sar        result             subshifted-        unused
                                          result
    rol/ror            result             zero               old_flags
    copy               old_flags          zero               unused.
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
                if cond_v == X86_CondTypes["CondLE"]:
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

                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), signed=True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == X86_CondTypes["CondO"]:
                    op_v = op.value
                    ret_cond = None
                    if op_v in {
                        X86_OpTypes["G_CC_OP_UMULB"],
                        X86_OpTypes["G_CC_OP_UMULW"],
                        X86_OpTypes["G_CC_OP_UMULL"],
                    }:
                        # dep_1 * dep_2 >= max_signed_byte/word/dword
                        ret = Expr.BinaryOp(
                            None,
                            "Mul",
                            (dep_1, dep_2),
                            bits=dep_1.bits * 2,
                            **ccall.tags,
                        )
                        max_signed = Expr.Const(
                            None,
                            None,
                            (1 << (dep_1.bits - 1)),
                            bits=dep_1.bits * 2,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(None, "CmpGE", (ret, max_signed), signed=False, bits=1, **ccall.tags)
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 >= max_signed_byte/word/dword
                        ret = Expr.BinaryOp(
                            None,
                            "Add",
                            (dep_1, dep_2),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        max_signed = Expr.Const(
                            None,
                            None,
                            (1 << (dep_1.bits - 1)),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(None, "CmpGE", (ret, max_signed), signed=False, bits=1, **ccall.tags)
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_INCB"],
                        X86_OpTypes["G_CC_OP_INCW"],
                        X86_OpTypes["G_CC_OP_INCL"],
                    }:
                        # dep_1 is the result
                        overflowed = Expr.Const(
                            None,
                            None,
                            1 << (dep_1.bits - 1),
                            dep_1.bits,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(None, "CmpEQ", (dep_1, overflowed), signed=False, bits=1, **ccall.tags)

                    if ret_cond is not None:
                        return Expr.ITE(
                            ccall.idx,
                            ret_cond,
                            Expr.Const(None, None, 0, 1, **ccall.tags),
                            Expr.Const(None, None, 1, 1, **ccall.tags),
                            **ccall.tags,
                        )
                elif cond_v == X86_CondTypes["CondZ"]:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 == 0
                        ret = Expr.BinaryOp(
                            None,
                            "Add",
                            (dep_1, dep_2),
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        zero = Expr.Const(
                            None,
                            None,
                            0,
                            dep_1.bits,
                            **ccall.tags,
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (ret, zero),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 - dep_2 == 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (dep_1, dep_2),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 == 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpEQ",
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v == X86_CondTypes["CondL"]:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 - dep_2 < 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLT",
                            (dep_1, dep_2),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 < 0
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLT",
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v in {
                    X86_CondTypes["CondBE"],
                    X86_CondTypes["CondB"],
                }:
                    op_v = op.value
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 <= 0  if CondBE
                        # dep_1 + dep_2 < 0   if CondB
                        ret = Expr.BinaryOp(
                            None,
                            "Add",
                            (dep_1, dep_2),
                            signed=False,
                            bits=dep_1.bits,
                            **ccall.tags,
                        )
                        zero = Expr.Const(
                            None,
                            None,
                            0,
                            dep_1.bits,
                            **ccall.tags,
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (ret, zero),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <= dep_2  if CondBE
                        # dep_1 < dep_2   if CondB
                        return Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, dep_2),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 <= 0  if CondBE
                        # dep_1 < 0   if CondB
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
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
