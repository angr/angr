from __future__ import annotations

from angr.ailment import Expr
from angr.analyses.decompiler.variable_map import variable_map_of
from angr.calling_conventions import SimCCUsercall
from angr.engines.vex.claripy.ccall import data

from .rewriter_base import CCallRewriterBase

AMD64_CondTypes = data["AMD64"]["CondTypes"]
AMD64_OpTypes = data["AMD64"]["OpTypes"]
AMD64_CondBitMasks = data["AMD64"]["CondBitMasks"]
AMD64_CondBitOffsets = data["AMD64"]["CondBitOffsets"]


class AMD64CCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for AMD64.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.callee == "amd64g_calculate_condition":
            cond = ccall.operands[0]
            op = ccall.operands[1]
            dep_1 = ccall.operands[2]
            dep_2 = ccall.operands[3]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                cond_v = cond.value_int
                op_v = op.value_int
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                            ccall.idx,
                            expr_op,
                            (dep_1, Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)),
                            False,
                            **ccall.tags,
                        )
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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

                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v == AMD64_OpTypes["G_CC_OP_COPY"]:
                        # dep_1 & G_CC_MASK_Z == 0 or dep_1 & G_CC_MASK_Z != 0

                        bitmask = AMD64_CondBitMasks["G_CC_MASK_Z"]
                        assert isinstance(bitmask, int)
                        flag = Expr.Const(self.ail_manager.next_atom(), bitmask, dep_1.bits)
                        masked_dep = Expr.BinaryOp(
                            self.ail_manager.next_atom(), "And", [dep_1, flag], False, **ccall.tags
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        r = Expr.BinaryOp(ccall.idx, expr_op, (masked_dep, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_DECB"],
                        AMD64_OpTypes["G_CC_OP_DECW"],
                        AMD64_OpTypes["G_CC_OP_DECL"],
                        AMD64_OpTypes["G_CC_OP_DECQ"],
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

                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # dep_1 is the result, dep_2 is always zero
                        # dep_1 <s 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, zero), True, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v == AMD64_CondTypes["CondNL"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # CondNL (jge) is SF == OF, i.e. dep_1 >=s dep_2

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

                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # and/or/xor clear OF, so CondNL = SF == 0, i.e. the result dep_1 >=s 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, zero), True, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

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
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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

                        cfadd_call = Expr.Call(
                            ccall.idx,
                            "__CFADD__",
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                        variable_map_of(self.ail_manager).set_calling_convention(
                            cfadd_call, SimCCUsercall(self.project.arch, [], None)
                        )
                        return cfadd_call
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 <u dep_2

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

                        r = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLT",
                            (dep_1, dep_2),
                            False,
                            **ccall.tags,
                        )
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
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
                    return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                elif (
                    cond_v == AMD64_CondTypes["CondNS"]
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
                    # dep_1 >= 0
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
                        "CmpGE",
                        (dep_1, dep_2),
                        True,
                        **ccall.tags,
                    )
                    return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v in {AMD64_CondTypes["CondO"], AMD64_CondTypes["CondNO"]}:
                    # overflow flag (jo / jno)
                    is_no = cond_v == AMD64_CondTypes["CondNO"]

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # and/or/xor always clear OF: CondO -> 0, CondNO -> 1
                        return Expr.Const(self.ail_manager.next_atom(), 1 if is_no else 0, ccall.bits, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        # signed overflow of dep_1 + dep_2
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
                        return self._overflow_helper(ccall, "__OFADD__", dep_1, dep_2, is_no)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # signed overflow of dep_1 - dep_2
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
                        return self._overflow_helper(ccall, "__OFSUB__", dep_1, dep_2, is_no)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_UMULB"],
                        AMD64_OpTypes["G_CC_OP_UMULW"],
                        AMD64_OpTypes["G_CC_OP_UMULL"],
                        AMD64_OpTypes["G_CC_OP_UMULQ"],
                    }:
                        # unsigned multiply overflow: high half of the full product is nonzero
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_UMULB"],
                            AMD64_OpTypes["G_CC_OP_UMULW"],
                            AMD64_OpTypes["G_CC_OP_UMULL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_UMULB"],
                            AMD64_OpTypes["G_CC_OP_UMULW"],
                            AMD64_OpTypes["G_CC_OP_UMULL"],
                            ccall.tags,
                        )
                        return self._overflow_helper(ccall, "__OFUMUL__", dep_1, dep_2, is_no)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SMULB"],
                        AMD64_OpTypes["G_CC_OP_SMULW"],
                        AMD64_OpTypes["G_CC_OP_SMULL"],
                        AMD64_OpTypes["G_CC_OP_SMULQ"],
                    }:
                        # signed multiply overflow
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SMULB"],
                            AMD64_OpTypes["G_CC_OP_SMULW"],
                            AMD64_OpTypes["G_CC_OP_SMULL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SMULB"],
                            AMD64_OpTypes["G_CC_OP_SMULW"],
                            AMD64_OpTypes["G_CC_OP_SMULL"],
                            ccall.tags,
                        )
                        return self._overflow_helper(ccall, "__OFSMUL__", dep_1, dep_2, is_no)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_INCB"],
                        AMD64_OpTypes["G_CC_OP_INCW"],
                        AMD64_OpTypes["G_CC_OP_INCL"],
                        AMD64_OpTypes["G_CC_OP_INCQ"],
                    }:
                        # inc overflows only when the result is the signed minimum
                        nbits = self._op_nbits(
                            op_v,
                            AMD64_OpTypes["G_CC_OP_INCB"],
                            AMD64_OpTypes["G_CC_OP_INCW"],
                            AMD64_OpTypes["G_CC_OP_INCL"],
                        )
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_INCB"],
                            AMD64_OpTypes["G_CC_OP_INCW"],
                            AMD64_OpTypes["G_CC_OP_INCL"],
                            ccall.tags,
                        )
                        signmin = Expr.Const(self.ail_manager.next_atom(), 1 << (nbits - 1), dep_1.bits)
                        expr_op = "CmpNE" if is_no else "CmpEQ"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, signmin), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_DECB"],
                        AMD64_OpTypes["G_CC_OP_DECW"],
                        AMD64_OpTypes["G_CC_OP_DECL"],
                        AMD64_OpTypes["G_CC_OP_DECQ"],
                    }:
                        # dec overflows only when the result is the signed maximum
                        nbits = self._op_nbits(
                            op_v,
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                        )
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                            ccall.tags,
                        )
                        signmax = Expr.Const(self.ail_manager.next_atom(), (1 << (nbits - 1)) - 1, dep_1.bits)
                        expr_op = "CmpNE" if is_no else "CmpEQ"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, signmax), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v == AMD64_OpTypes["G_CC_OP_COPY"]:
                        # dep_1 holds the packed flags; test the stored OF bit
                        bitmask = AMD64_CondBitMasks["G_CC_MASK_O"]
                        assert isinstance(bitmask, int)
                        flag = Expr.Const(self.ail_manager.next_atom(), bitmask, dep_1.bits)
                        masked_dep = Expr.BinaryOp(
                            self.ail_manager.next_atom(), "And", [dep_1, flag], False, **ccall.tags
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        expr_op = "CmpEQ" if is_no else "CmpNE"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (masked_dep, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

        elif ccall.callee == "amd64g_calculate_rflags_c":
            # calculate the carry flag
            op = ccall.operands[0]
            dep_1 = ccall.operands[1]
            dep_2 = ccall.operands[2]
            ndep = ccall.operands[3]
            if isinstance(op, Expr.Const):
                op_v = op.value_int
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
                        self.ail_manager.next_atom(),
                        Expr.BinaryOp(
                            self.ail_manager.next_atom(),
                            "CmpLE",
                            [
                                Expr.BinaryOp(self.ail_manager.next_atom(), "Add", [dep_1, dep_2], False),
                                dep_1,
                            ],
                            False,
                        ),
                        Expr.Const(self.ail_manager.next_atom(), 0, ccall.bits),
                        Expr.Const(self.ail_manager.next_atom(), 1, ccall.bits),
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
                        self.ail_manager.next_atom(),
                        "CmpLT",
                        [
                            dep_1,
                            dep_2,
                        ],
                        False,
                    )
                    if cf.bits == ccall.bits:
                        return cf
                    return Expr.Convert(self.ail_manager.next_atom(), cf.bits, ccall.bits, False, cf, **ccall.tags)

                if op_v in {
                    AMD64_OpTypes["G_CC_OP_DECB"],
                    AMD64_OpTypes["G_CC_OP_DECW"],
                    AMD64_OpTypes["G_CC_OP_DECL"],
                    AMD64_OpTypes["G_CC_OP_DECQ"],
                }:
                    # pc_actions_DEC
                    bitmask = AMD64_CondBitMasks["G_CC_MASK_C"]
                    bitmask_1 = AMD64_CondBitOffsets["G_CC_SHIFT_C"]
                    assert isinstance(bitmask, int) and isinstance(bitmask_1, int)
                    return Expr.BinaryOp(
                        self.ail_manager.next_atom(),
                        "Shr",
                        [
                            Expr.BinaryOp(
                                self.ail_manager.next_atom(),
                                "And",
                                [ndep, Expr.Const(self.ail_manager.next_atom(), bitmask, 64)],
                                False,
                            ),
                            Expr.Const(self.ail_manager.next_atom(), bitmask_1, 64),
                        ],
                        False,
                        **ccall.tags,
                    )

        return None

    @staticmethod
    def _op_nbits(op_v: int, type_8bit, type_16bit, type_32bit) -> int:
        if op_v == type_8bit:
            return 8
        if op_v == type_16bit:
            return 16
        if op_v == type_32bit:
            return 32
        return 64

    def _overflow_helper(self, ccall, name: str, dep_1, dep_2, is_no: bool):
        # Emit a named overflow-helper call (mirrors the __CFADD__ arm). The helper
        # returns a 0/1 flag; for the negated condition (CondNO) compare it to 0.
        call = Expr.Call(
            ccall.idx,
            name,
            args=[dep_1, dep_2],
            bits=ccall.bits,
            **ccall.tags,
        )
        variable_map_of(self.ail_manager).set_calling_convention(call, SimCCUsercall(self.project.arch, [], None))
        if not is_no:
            return call
        zero = Expr.Const(self.ail_manager.next_atom(), 0, ccall.bits)
        r = Expr.BinaryOp(self.ail_manager.next_atom(), "CmpEQ", (call, zero), False, **ccall.tags)
        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)

    def _fix_size(self, expr, op_v: int, type_8bit, type_16bit, type_32bit, tags):
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
                return Expr.Const(expr.idx, expr.value_int & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(self.ail_manager.next_atom(), 64, bits, False, expr, **tags)
        return expr
