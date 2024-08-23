from __future__ import annotations
from ailment import Expr, Stmt

from angr.calling_conventions import SimCCUsercall
from angr.engines.vex.claripy.ccall import data
from .rewriter_base import CCallRewriterBase


AMD64_CondTypes = data["AMD64"]["CondTypes"]
AMD64_OpTypes = data["AMD64"]["OpTypes"]
AMD64_CondBitMasks = data["AMD64"]["CondBitMasks"]
AMD64_CondBitOffsets = data["AMD64"]["CondBitOffsets"]


class AMD64CCallRewriter(CCallRewriterBase):
    """
    Implements ccall rewriter for AMD64.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.cee_name == "amd64g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value
                op_v = op.value
                if cond_v == AMD64_CondTypes["CondLE"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 <=s dep_2
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if (
                        op_v
                        in {
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            AMD64_OpTypes["G_CC_OP_LOGICQ"],
                        }
                        and isinstance(dep_2, Expr.Const)
                        and dep_2.value == 0
                    ):
                        # dep_1 >=s 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE",
                            (dep_1, dep_2),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondNLE"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 >s dep_2
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpGT", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if (
                        op_v
                        in {
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            AMD64_OpTypes["G_CC_OP_LOGICQ"],
                        }
                        and isinstance(dep_2, Expr.Const)
                        and dep_2.value == 0
                    ):
                        # dep_1 >s 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(
                            ccall.idx,
                            "CmpGT",
                            (dep_1, dep_2),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v in {AMD64_CondTypes["CondZ"], AMD64_CondTypes["CondNZ"]}:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 == 0 or dep_1 - dep_2 != 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # dep_1 == 0 or dep_1 != 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        r = Expr.BinaryOp(
                            ccall.idx, expr_op, (dep_1, Expr.Const(None, None, 0, dep_1.bits)), False, **ccall.tags
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SHRB"],
                        AMD64_OpTypes["G_CC_OP_SHRW"],
                        AMD64_OpTypes["G_CC_OP_SHRL"],
                        AMD64_OpTypes["G_CC_OP_SHRQ"],
                    }:
                        # dep_1 == 0 or dep_1 != 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SHRB"],
                            AMD64_OpTypes["G_CC_OP_SHRW"],
                            AMD64_OpTypes["G_CC_OP_SHRL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v == AMD64_OpTypes["G_CC_OP_COPY"]:
                        # dep_1 & G_CC_MASK_Z == 0 or dep_1 & G_CC_MASK_Z != 0

                        flag = Expr.Const(None, None, AMD64_CondBitMasks["G_CC_MASK_Z"], dep_1.bits)
                        masked_dep = Expr.BinaryOp(None, "And", [dep_1, flag], False, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        r = Expr.BinaryOp(ccall.idx, expr_op, (masked_dep, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondL"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 <s 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondNBE"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 > 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpGT", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondB"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        # __CFADD__(dep_1, dep_2)

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                        )

                        return Stmt.Call(
                            ccall.idx,
                            "__CFADD__",
                            calling_convention=SimCCUsercall(self.arch, [], None),
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                elif (
                    cond_v == AMD64_CondTypes["CondS"]
                    and op_v
                    in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }
                    and isinstance(dep_2, Expr.Const)
                    and dep_2.value == 0
                ):
                    # dep_1 < 0

                    dep_1 = self._fix_size(
                        dep_1,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        ccall.tags,
                    )
                    dep_2 = self._fix_size(
                        dep_2,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        ccall.tags,
                    )

                    r = Expr.BinaryOp(
                        ccall.idx,
                        "CmpLT",
                        (dep_1, dep_2),
                        True,
                        **ccall.tags,
                    )
                    return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

        elif ccall.cee_name == "amd64g_calculate_rflags_c":
            # calculate the carry flag
            op = ccall.operands[0]
            dep_1 = ccall.operands[1]
            dep_2 = ccall.operands[2]
            ndep = ccall.operands[3]
            if isinstance(op, Expr.Const):
                op_v = op.value
                if op_v in {
                    AMD64_OpTypes["G_CC_OP_ADDB"],
                    AMD64_OpTypes["G_CC_OP_ADDW"],
                    AMD64_OpTypes["G_CC_OP_ADDL"],
                    AMD64_OpTypes["G_CC_OP_ADDQ"],
                }:
                    # pc_actions_ADD

                    dep_1 = self._fix_size(
                        dep_1,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        ccall.tags,
                    )
                    dep_2 = self._fix_size(
                        dep_2,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        ccall.tags,
                    )

                    return Expr.ITE(
                        None,
                        Expr.BinaryOp(
                            None,
                            "CmpLE",
                            [
                                Expr.BinaryOp(None, "Add", [dep_1, dep_2], False),
                                dep_1,
                            ],
                            False,
                        ),
                        Expr.Const(None, None, 0, ccall.bits),
                        Expr.Const(None, None, 1, ccall.bits),
                        **ccall.tags,
                    )

                if op_v in {
                    AMD64_OpTypes["G_CC_OP_SUBB"],
                    AMD64_OpTypes["G_CC_OP_SUBW"],
                    AMD64_OpTypes["G_CC_OP_SUBL"],
                    AMD64_OpTypes["G_CC_OP_SUBQ"],
                }:
                    # pc_actions_SUB

                    dep_1 = self._fix_size(
                        dep_1,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        ccall.tags,
                    )
                    dep_2 = self._fix_size(
                        dep_2,
                        op_v,
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        ccall.tags,
                    )

                    cf = Expr.BinaryOp(
                        None,
                        "CmpLT",
                        [
                            dep_1,
                            dep_2,
                        ],
                        False,
                    )
                    if cf.bits == ccall.bits:
                        return cf
                    return Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)

                if op_v in {
                    AMD64_OpTypes["G_CC_OP_DECB"],
                    AMD64_OpTypes["G_CC_OP_DECW"],
                    AMD64_OpTypes["G_CC_OP_DECL"],
                    AMD64_OpTypes["G_CC_OP_DECQ"],
                }:
                    # pc_actions_DEC
                    return Expr.BinaryOp(
                        None,
                        "Shr",
                        [
                            Expr.BinaryOp(
                                None,
                                "And",
                                [ndep, Expr.Const(None, None, AMD64_CondBitMasks["G_CC_MASK_C"], 64)],
                                False,
                            ),
                            Expr.Const(None, None, AMD64_CondBitOffsets["G_CC_SHIFT_C"], 64),
                        ],
                        False,
                        **ccall.tags,
                    )

        return None

    @staticmethod
    def _fix_size(expr, op_v: int, type_8bit, type_16bit, type_32bit, tags):
        if op_v == type_8bit:
            bits = 8
        elif op_v == type_16bit:
            bits = 16
        elif op_v == type_32bit:
            bits = 32
        else:
            bits = 64
        if bits < 64:
            if isinstance(expr, Expr.Const):
                return Expr.Const(expr.idx, None, expr.value & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(None, 64, bits, False, expr, **tags)
        return expr
