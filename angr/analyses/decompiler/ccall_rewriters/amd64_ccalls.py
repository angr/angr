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

# every bit amd64g_calculate_rflags_all can set; all other bits of the packed word are zero
AMD64_RFLAGS_ALL_MASK = (
    AMD64_CondBitMasks["G_CC_MASK_O"]
    | AMD64_CondBitMasks["G_CC_MASK_S"]
    | AMD64_CondBitMasks["G_CC_MASK_Z"]
    | AMD64_CondBitMasks["G_CC_MASK_A"]
    | AMD64_CondBitMasks["G_CC_MASK_C"]
    | AMD64_CondBitMasks["G_CC_MASK_P"]
)

# cc_op -> (family, operand width in bits), for the families rflags_all can rebuild
AMD64_RFLAGS_ALL_FAMILIES: dict[int, tuple[str, int]] = {
    AMD64_OpTypes[f"G_CC_OP_{fam}{suffix}"]: (fam, nbits)
    for fam in ("ADD", "SUB", "LOGIC", "INC", "DEC")
    for suffix, nbits in (("B", 8), ("W", 16), ("L", 32), ("Q", 64))
}


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
                        # dep_1 holds the old flags: ZF is *set* iff the masked bit is non-zero
                        expr_op = "CmpNE" if cond_v == AMD64_CondTypes["CondZ"] else "CmpEQ"

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
                elif cond_v in {AMD64_CondTypes["CondB"], AMD64_CondTypes["CondBE"]}:
                    # CondB tests CF; CondBE tests CF | ZF
                    is_be = cond_v == AMD64_CondTypes["CondBE"]
                    if not is_be and op_v in {
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
                        # CF is dep_1 <u dep_2 and ZF is dep_1 == dep_2, so
                        # dep_1 <u dep_2 for CondB, dep_1 <=u dep_2 for CondBE

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
                            "CmpLE" if is_be else "CmpLT",
                            (dep_1, dep_2),
                            False,
                            **ccall.tags,
                        )
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # and/or/xor always clear CF, so CondB is never true and CondBE degenerates to ZF
                        if not is_be:
                            return Expr.Const(self.ail_manager.next_atom(), 0, ccall.bits, **ccall.tags)

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ", (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondNB"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        # CondNB is !CF, i.e. the negation of the __CFADD__ carry test that CondB
                        # emits. An inline (a + b) >=u a comparison would be wrong here: C integer
                        # promotion keeps sub-int additions from wrapping, making it a tautology at
                        # 8/16-bit widths.

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
                            self.ail_manager.next_atom(),
                            "__CFADD__",
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                        variable_map_of(self.ail_manager).set_calling_convention(
                            cfadd_call, SimCCUsercall(self.project.arch, [], None)
                        )
                        zero = Expr.Const(self.ail_manager.next_atom(), 0, cfadd_call.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ", (cfadd_call, zero), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 >=u dep_2

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

                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # and/or/xor always clear CF, so CondNB is always true
                        return Expr.Const(self.ail_manager.next_atom(), 1, ccall.bits, **ccall.tags)
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

        elif ccall.callee == "amd64g_calculate_rflags_all":
            op = ccall.operands[0]
            if isinstance(op, Expr.Const):
                return self._rewrite_rflags_all(
                    ccall, op.value_int, ccall.operands[1], ccall.operands[2], ccall.operands[3]
                )

        return None

    #
    # amd64g_calculate_rflags_all
    #

    def _rewrite_rflags_all(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        ndep: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        Rebuild the packed rflags word that amd64g_calculate_rflags_all returns: bit C(0), P(2),
        A(4), Z(6), S(7), O(11); all other bits are zero.
        """
        bits = ccall.bits
        if bits != 64:
            return None
        tags = ccall.tags

        if op_v == AMD64_OpTypes["G_CC_OP_COPY"]:
            # cc_dep1 already holds the flags; only the six modelled bits survive
            if dep_1.bits != bits:
                return None
            return self._binop("And", dep_1, self._const(AMD64_RFLAGS_ALL_MASK, bits), False, tags, idx=ccall.idx)

        family_nbits = AMD64_RFLAGS_ALL_FAMILIES.get(op_v)
        if family_nbits is None:
            return None
        family, nbits = family_nbits

        d1 = self._narrow(dep_1, nbits, tags)
        # positioned 64-bit terms that get Or'ed into the final word
        terms: list[Expr.Expression] = []

        if family == "LOGIC":
            # and/or/xor: cc_dep1 is the result; CF, AF and OF are cleared
            res = d1
            terms.append(self._parity_term(res, nbits, bits, tags))
            terms.append(self._bit_term(self._is_zero(res, tags), "G_CC_SHIFT_Z", bits, tags))
            terms.append(self._bit_term(self._is_neg(res, tags), "G_CC_SHIFT_S", bits, tags))
        elif family in {"ADD", "SUB"}:
            d2 = self._narrow(dep_2, nbits, tags)
            res = self._binop("Add" if family == "ADD" else "Sub", d1, d2, False, tags)
            if family == "ADD":
                cf = self._binop("CmpLT", res, d1, False, tags)  # unsigned wrap-around
                # OF = msb(~(d1 ^ d2) & (d1 ^ res))
                of_word = self._binop(
                    "And",
                    self._unop("BitwiseNeg", self._binop("Xor", d1, d2, False, tags), tags),
                    self._binop("Xor", d1, res, False, tags),
                    False,
                    tags,
                )
            else:
                cf = self._binop("CmpLT", d1, d2, False, tags)
                # OF = msb((d1 ^ d2) & (d1 ^ res))
                of_word = self._binop(
                    "And",
                    self._binop("Xor", d1, d2, False, tags),
                    self._binop("Xor", d1, res, False, tags),
                    False,
                    tags,
                )
            terms.append(self._bit_term(cf, "G_CC_SHIFT_C", bits, tags))
            terms.append(self._parity_term(res, nbits, bits, tags))
            terms.append(self._af_term(res, d1, d2, bits, tags))
            terms.append(self._bit_term(self._is_zero(res, tags), "G_CC_SHIFT_Z", bits, tags))
            terms.append(self._bit_term(self._is_neg(res, tags), "G_CC_SHIFT_S", bits, tags))
            terms.append(self._bit_term(self._is_neg(of_word, tags), "G_CC_SHIFT_O", bits, tags))
        else:
            # INC/DEC: cc_dep1 is the result, CF is carried over from cc_ndep untouched
            if ndep.bits != bits:
                return None
            res = d1
            one = self._const(1, nbits)
            # the pre-op value, which AF is computed against
            other = self._binop("Sub" if family == "INC" else "Add", res, one, False, tags)
            # OF is only set at the signed extreme the op crossed
            extreme = 1 << (nbits - 1) if family == "INC" else (1 << (nbits - 1)) - 1
            terms.append(self._binop("And", ndep, self._const(AMD64_CondBitMasks["G_CC_MASK_C"], bits), False, tags))
            terms.append(self._parity_term(res, nbits, bits, tags))
            terms.append(self._af_term(res, other, one, bits, tags))
            terms.append(self._bit_term(self._is_zero(res, tags), "G_CC_SHIFT_Z", bits, tags))
            terms.append(self._bit_term(self._is_neg(res, tags), "G_CC_SHIFT_S", bits, tags))
            terms.append(
                self._bit_term(
                    self._binop("CmpEQ", res, self._const(extreme, nbits), False, tags),
                    "G_CC_SHIFT_O",
                    bits,
                    tags,
                )
            )

        result = terms[0]
        for term in terms[1:]:
            result = self._binop("Or", result, term, False, tags)
        return result

    def _is_zero(self, expr, tags):
        return self._binop("CmpEQ", expr, self._const(0, expr.bits), False, tags)

    def _is_neg(self, expr, tags):
        # signed < 0 is exactly the most significant bit
        return self._binop("CmpLT", expr, self._const(0, expr.bits), True, tags)

    def _bit_term(self, bit_expr, shift_name: str, bits: int, tags):
        """Widen a 1-bit flag expression to `bits` and move it to its rflags position."""
        shift = AMD64_CondBitOffsets[shift_name]
        assert isinstance(shift, int)
        widened = Expr.Convert(self.ail_manager.next_atom(), bit_expr.bits, bits, False, bit_expr, **tags)
        if shift == 0:
            return widened
        return self._binop("Shl", widened, self._const(shift, 8), False, tags)

    def _af_term(self, res, arg_l, arg_r, bits: int, tags):
        """AF = bit 4 of (res ^ arg_l ^ arg_r); the mask leaves it already in position."""
        xored = self._binop("Xor", self._binop("Xor", res, arg_l, False, tags), arg_r, False, tags)
        masked = self._binop("And", xored, self._const(AMD64_CondBitMasks["G_CC_MASK_A"], res.bits), False, tags)
        if masked.bits == bits:
            return masked
        return Expr.Convert(self.ail_manager.next_atom(), masked.bits, bits, False, masked, **tags)

    def _parity_term(self, res, nbits: int, bits: int, tags):
        """
        PF = 1 iff the low byte of the result has an even number of set bits.

        Fold the byte down to a nibble, then index the 16-entry even-parity table 0x9669. This has
        to stay a pure expression: a helper call would make every rewritten flags assignment look
        side-effecting, and dead flag computations would stop being removable.
        """
        low_byte = self._narrow(res, 8, tags) if nbits > 8 else res
        shifted = self._binop("Shr", low_byte, self._const(4, 8), False, tags)
        folded = self._binop("Xor", low_byte, shifted, False, tags)
        index = self._binop("And", folded, self._const(0xF, 8), False, tags)
        table = self._binop("Shr", self._const(0x9669, bits), index, False, tags)
        bit = self._binop("And", table, self._const(1, bits), False, tags)
        return self._binop("Shl", bit, self._const(AMD64_CondBitOffsets["G_CC_SHIFT_P"], 8), False, tags)

    def _const(self, value: int, bits: int) -> Expr.Const:
        return Expr.Const(self.ail_manager.next_atom(), value, bits)

    def _unop(self, op: str, operand, tags):
        return Expr.UnaryOp(self.ail_manager.next_atom(), op, operand, **tags)

    def _binop(self, op: str, op0, op1, signed: bool, tags, idx: int | None = None):
        return Expr.BinaryOp(self.ail_manager.next_atom() if idx is None else idx, op, [op0, op1], signed, **tags)

    def _narrow(self, expr, nbits: int, tags):
        if expr.bits == nbits:
            return expr
        if isinstance(expr, Expr.Const):
            return Expr.Const(expr.idx, expr.value_int & ((1 << nbits) - 1), nbits, **tags)
        return Expr.Convert(self.ail_manager.next_atom(), expr.bits, nbits, False, expr, **tags)

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
