from __future__ import annotations
from angr.ailment import Expr

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
            ndep = ccall.operands[4]
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
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
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
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                            signed=True,
                        )

                        r = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE",
                            (dep_1, dep_2),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_DECB"],
                        AMD64_OpTypes["G_CC_OP_DECW"],
                        AMD64_OpTypes["G_CC_OP_DECL"],
                        AMD64_OpTypes["G_CC_OP_DECQ"],
                    }:
                        # Triggered by: procd (decl)
                        # For dec ops, DEP1 is the result.
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                            ccall.tags,
                            signed=True,
                        )
                        # DEC: CondLE is (ZF==1) or (SF!=OF). For DEC, OF=1 iff res == max_signed.
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        max_s = (1 << (dep_1.bits - 1)) - 1
                        max_c = Expr.Const(None, None, max_s, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (dep_1, zero), False, bits=1, **ccall.tags)
                        sf = Expr.BinaryOp(None, "CmpLT", (dep_1, zero), True, bits=1, **ccall.tags)
                        of = Expr.BinaryOp(None, "CmpEQ", (dep_1, max_c), False, bits=1, **ccall.tags)
                        sf_xor_of = Expr.BinaryOp(None, "CmpNE", (sf, of), False, bits=1, **ccall.tags)
                        le = Expr.BinaryOp(None, "Or", (zf, sf_xor_of), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, le.bits, ccall.bits, False, le, **ccall.tags)
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
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
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
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                            signed=True,
                        )

                        r = Expr.BinaryOp(
                            ccall.idx,
                            "CmpGT",
                            (dep_1, dep_2),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_DECB"],
                        AMD64_OpTypes["G_CC_OP_DECW"],
                        AMD64_OpTypes["G_CC_OP_DECL"],
                        AMD64_OpTypes["G_CC_OP_DECQ"],
                    }:
                        # Triggered by: procd (decl)
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                            ccall.tags,
                            signed=True,
                        )
                        # DEC: CondNLE is (ZF==0) and (SF==OF). For DEC, OF=1 iff res == max_signed.
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        max_s = (1 << (dep_1.bits - 1)) - 1
                        max_c = Expr.Const(None, None, max_s, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (dep_1, zero), False, bits=1, **ccall.tags)
                        sf = Expr.BinaryOp(None, "CmpLT", (dep_1, zero), True, bits=1, **ccall.tags)
                        of = Expr.BinaryOp(None, "CmpEQ", (dep_1, max_c), False, bits=1, **ccall.tags)
                        not_zf = Expr.UnaryOp(None, "Not", zf, bits=1, **ccall.tags)
                        sf_eq_of = Expr.BinaryOp(None, "CmpEQ", (sf, of), False, bits=1, **ccall.tags)
                        nle = Expr.BinaryOp(None, "And", (not_zf, sf_eq_of), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, nle.bits, ccall.bits, False, nle, **ccall.tags)
                elif cond_v in {AMD64_CondTypes["CondZ"], AMD64_CondTypes["CondNZ"]}:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        # dep_1 + dep_2 == 0 or dep_1 + dep_2 != 0

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
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"
                        ret = Expr.BinaryOp(None, "Add", (dep_1, dep_2), False, bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (ret, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
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
                        AMD64_OpTypes["G_CC_OP_SHLB"],
                        AMD64_OpTypes["G_CC_OP_SHLW"],
                        AMD64_OpTypes["G_CC_OP_SHLL"],
                        AMD64_OpTypes["G_CC_OP_SHLQ"],
                    }:
                        # Triggered by: gawk
                        # dep_1 == 0 or dep_1 != 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SHLB"],
                            AMD64_OpTypes["G_CC_OP_SHLW"],
                            AMD64_OpTypes["G_CC_OP_SHLL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
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

                        bitmask = AMD64_CondBitMasks["G_CC_MASK_Z"]
                        assert isinstance(bitmask, int)
                        flag = Expr.Const(None, None, bitmask, dep_1.bits)
                        masked_dep = Expr.BinaryOp(None, "And", [dep_1, flag], False, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        expr_op = "CmpNE" if cond_v == AMD64_CondTypes["CondZ"] else "CmpEQ"

                        r = Expr.BinaryOp(ccall.idx, expr_op, (masked_dep, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_INCB"],
                        AMD64_OpTypes["G_CC_OP_INCW"],
                        AMD64_OpTypes["G_CC_OP_INCL"],
                        AMD64_OpTypes["G_CC_OP_INCQ"],
                    }:
                        # dep_1 == 0 or dep_1 != 0

                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_INCB"],
                            AMD64_OpTypes["G_CC_OP_INCW"],
                            AMD64_OpTypes["G_CC_OP_INCL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
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
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                            ccall.tags,
                        )
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"

                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB result == 0 or result != 0
                        _, _, _, result = self._sbb_prep(dep_1, dep_2, ndep, op_v, ccall.tags)
                        expr_op = "CmpEQ" if cond_v == AMD64_CondTypes["CondZ"] else "CmpNE"
                        zero = Expr.Const(None, None, 0, result.bits, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (result, zero), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v in {AMD64_CondTypes["CondO"], AMD64_CondTypes["CondNO"]}:
                    # Triggered by: gawk (mulq), tar (addq)
                    negate = cond_v == AMD64_CondTypes["CondNO"]

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                            signed=True,
                        )
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        of_tags = {**ccall.tags, "overflow_signed": True}
                        r = Expr.Call(
                            ccall.idx,
                            "__OFADD__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **of_tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_UMULB"],
                        AMD64_OpTypes["G_CC_OP_UMULW"],
                        AMD64_OpTypes["G_CC_OP_UMULL"],
                        AMD64_OpTypes["G_CC_OP_UMULQ"],
                    }:
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
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        of_tags = {**ccall.tags, "overflow_signed": False}
                        r = Expr.Call(
                            ccall.idx,
                            "__OFMUL__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **of_tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SMULB"],
                        AMD64_OpTypes["G_CC_OP_SMULW"],
                        AMD64_OpTypes["G_CC_OP_SMULL"],
                        AMD64_OpTypes["G_CC_OP_SMULQ"],
                    }:
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SMULB"],
                            AMD64_OpTypes["G_CC_OP_SMULW"],
                            AMD64_OpTypes["G_CC_OP_SMULL"],
                            ccall.tags,
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SMULB"],
                            AMD64_OpTypes["G_CC_OP_SMULW"],
                            AMD64_OpTypes["G_CC_OP_SMULL"],
                            ccall.tags,
                            signed=True,
                        )
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        of_tags = {**ccall.tags, "overflow_signed": True}
                        r = Expr.Call(
                            ccall.idx,
                            "__OFMUL__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **of_tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r
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
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
                        )

                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

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
                            signed=True,
                        )
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, zero), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB CondL: signed less-than using extended precision
                        dep_1n, arg2, carry_n, _ = self._sbb_prep(
                            dep_1,
                            dep_2,
                            ndep,
                            op_v,
                            ccall.tags,
                            signed=True,
                        )
                        ext = dep_1n.bits * 2
                        a_ext = Expr.Convert(None, dep_1n.bits, ext, True, dep_1n, **ccall.tags)
                        b_ext = Expr.Convert(None, arg2.bits, ext, True, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, carry_n.bits, ext, False, carry_n, **ccall.tags)
                        rhs = Expr.BinaryOp(None, "Add", (b_ext, c_ext), False, bits=ext, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (a_ext, rhs), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v == AMD64_CondTypes["CondNL"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 >=s 0
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
                        )
                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, dep_2), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                    }:
                        # dep_1 >=s 0
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            ccall.tags,
                            signed=True,
                        )
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, zero), True, **ccall.tags)
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
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB: !CF && !ZF = no borrow and result!=0
                        dep_1n, arg2, carry_n, result = self._sbb_prep(
                            dep_1,
                            dep_2,
                            ndep,
                            op_v,
                            ccall.tags,
                        )
                        ext = dep_1n.bits + 1
                        a_ext = Expr.Convert(None, dep_1n.bits, ext, False, dep_1n, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1n.bits, ext, False, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1n.bits, ext, False, carry_n, **ccall.tags)
                        rhs = Expr.BinaryOp(None, "Add", (b_ext, c_ext), False, bits=ext, **ccall.tags)
                        no_cf = Expr.BinaryOp(None, "CmpGE", (a_ext, rhs), False, bits=1, **ccall.tags)
                        zero = Expr.Const(None, None, 0, result.bits, **ccall.tags)
                        no_zf = Expr.BinaryOp(None, "CmpNE", (result, zero), False, bits=1, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "And", (no_cf, no_zf), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondBE"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 <=u 0
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
                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB: CF || ZF = borrow or result==0
                        dep_1n, arg2, carry_n, result = self._sbb_prep(
                            dep_1,
                            dep_2,
                            ndep,
                            op_v,
                            ccall.tags,
                        )
                        ext = dep_1n.bits + 1
                        a_ext = Expr.Convert(None, dep_1n.bits, ext, False, dep_1n, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1n.bits, ext, False, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1n.bits, ext, False, carry_n, **ccall.tags)
                        rhs = Expr.BinaryOp(None, "Add", (b_ext, c_ext), False, bits=ext, **ccall.tags)
                        cf = Expr.BinaryOp(None, "CmpLT", (a_ext, rhs), False, bits=1, **ccall.tags)
                        zero = Expr.Const(None, None, 0, result.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (result, zero), False, bits=1, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "Or", (cf, zf), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == AMD64_CondTypes["CondNB"]:
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        # dep_1 - dep_2 >=u 0
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
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB: no borrow = dep_1 >=u (arg2 + carry), using extended precision
                        dep_1n, arg2, carry_n, _ = self._sbb_prep(dep_1, dep_2, ndep, op_v, ccall.tags)
                        ext = dep_1n.bits + 1
                        a_ext = Expr.Convert(None, dep_1n.bits, ext, False, dep_1n, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1n.bits, ext, False, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1n.bits, ext, False, carry_n, **ccall.tags)
                        rhs = Expr.BinaryOp(None, "Add", (b_ext, c_ext), False, bits=ext, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "CmpGE", (a_ext, rhs), False, bits=1, **ccall.tags)
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

                        return Expr.Call(
                            ccall.idx,
                            "__CFADD__",
                            calling_convention=SimCCUsercall(self.project.arch, [], None),
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
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
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # Triggered by: uhttpd (sbbq)
                        # Borrow flag for sbb: a <u (arg2 + old_carry)
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SBBB"],
                            AMD64_OpTypes["G_CC_OP_SBBW"],
                            AMD64_OpTypes["G_CC_OP_SBBL"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SBBB"],
                            AMD64_OpTypes["G_CC_OP_SBBW"],
                            AMD64_OpTypes["G_CC_OP_SBBL"],
                            ccall.tags,
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits)],
                            False,
                            bits=ndep.bits,
                            **ccall.tags,
                        )
                        carry_ext = (
                            Expr.Convert(None, carry.bits, dep_1.bits, False, carry, **ccall.tags)
                            if carry.bits != dep_1.bits
                            else carry
                        )
                        arg2 = Expr.BinaryOp(None, "Xor", (dep_2, carry_ext), bits=dep_1.bits, **ccall.tags)

                        ext_bits = dep_1.bits + 1
                        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, dep_1, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, carry_ext, **ccall.tags)
                        rhs_ext = Expr.BinaryOp(None, "Add", (b_ext, c_ext), bits=ext_bits, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "CmpLT", (a_ext, rhs_ext), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v in {AMD64_CondTypes["CondS"], AMD64_CondTypes["CondNS"]}:
                    # Triggered by: gawk (shlq), procd (incl)
                    expr_op = "CmpLT" if cond_v == AMD64_CondTypes["CondS"] else "CmpGE"

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_ADDB"],
                        AMD64_OpTypes["G_CC_OP_ADDW"],
                        AMD64_OpTypes["G_CC_OP_ADDL"],
                        AMD64_OpTypes["G_CC_OP_ADDQ"],
                    }:
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_ADDB"],
                            AMD64_OpTypes["G_CC_OP_ADDW"],
                            AMD64_OpTypes["G_CC_OP_ADDL"],
                            ccall.tags,
                            signed=True,
                        )
                        ret = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (ret, zero), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SUBB"],
                        AMD64_OpTypes["G_CC_OP_SUBW"],
                        AMD64_OpTypes["G_CC_OP_SUBL"],
                        AMD64_OpTypes["G_CC_OP_SUBQ"],
                    }:
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            AMD64_OpTypes["G_CC_OP_SUBB"],
                            AMD64_OpTypes["G_CC_OP_SUBW"],
                            AMD64_OpTypes["G_CC_OP_SUBL"],
                            ccall.tags,
                            signed=True,
                        )
                        ret = Expr.BinaryOp(None, "Sub", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (ret, zero), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_LOGICB"],
                        AMD64_OpTypes["G_CC_OP_LOGICW"],
                        AMD64_OpTypes["G_CC_OP_LOGICL"],
                        AMD64_OpTypes["G_CC_OP_LOGICQ"],
                        AMD64_OpTypes["G_CC_OP_SHLB"],
                        AMD64_OpTypes["G_CC_OP_SHLW"],
                        AMD64_OpTypes["G_CC_OP_SHLL"],
                        AMD64_OpTypes["G_CC_OP_SHLQ"],
                        AMD64_OpTypes["G_CC_OP_SHRB"],
                        AMD64_OpTypes["G_CC_OP_SHRW"],
                        AMD64_OpTypes["G_CC_OP_SHRL"],
                        AMD64_OpTypes["G_CC_OP_SHRQ"],
                        AMD64_OpTypes["G_CC_OP_INCB"],
                        AMD64_OpTypes["G_CC_OP_INCW"],
                        AMD64_OpTypes["G_CC_OP_INCL"],
                        AMD64_OpTypes["G_CC_OP_INCQ"],
                        AMD64_OpTypes["G_CC_OP_DECB"],
                        AMD64_OpTypes["G_CC_OP_DECW"],
                        AMD64_OpTypes["G_CC_OP_DECL"],
                        AMD64_OpTypes["G_CC_OP_DECQ"],
                    }:
                        if op_v in {
                            AMD64_OpTypes["G_CC_OP_LOGICB"],
                            AMD64_OpTypes["G_CC_OP_LOGICW"],
                            AMD64_OpTypes["G_CC_OP_LOGICL"],
                            AMD64_OpTypes["G_CC_OP_LOGICQ"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                AMD64_OpTypes["G_CC_OP_LOGICB"],
                                AMD64_OpTypes["G_CC_OP_LOGICW"],
                                AMD64_OpTypes["G_CC_OP_LOGICL"],
                                ccall.tags,
                                signed=True,
                            )
                        elif op_v in {
                            AMD64_OpTypes["G_CC_OP_SHLB"],
                            AMD64_OpTypes["G_CC_OP_SHLW"],
                            AMD64_OpTypes["G_CC_OP_SHLL"],
                            AMD64_OpTypes["G_CC_OP_SHLQ"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                AMD64_OpTypes["G_CC_OP_SHLB"],
                                AMD64_OpTypes["G_CC_OP_SHLW"],
                                AMD64_OpTypes["G_CC_OP_SHLL"],
                                ccall.tags,
                                signed=True,
                            )
                        elif op_v in {
                            AMD64_OpTypes["G_CC_OP_SHRB"],
                            AMD64_OpTypes["G_CC_OP_SHRW"],
                            AMD64_OpTypes["G_CC_OP_SHRL"],
                            AMD64_OpTypes["G_CC_OP_SHRQ"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                AMD64_OpTypes["G_CC_OP_SHRB"],
                                AMD64_OpTypes["G_CC_OP_SHRW"],
                                AMD64_OpTypes["G_CC_OP_SHRL"],
                                ccall.tags,
                                signed=True,
                            )
                        elif op_v in {
                            AMD64_OpTypes["G_CC_OP_INCB"],
                            AMD64_OpTypes["G_CC_OP_INCW"],
                            AMD64_OpTypes["G_CC_OP_INCL"],
                            AMD64_OpTypes["G_CC_OP_INCQ"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                AMD64_OpTypes["G_CC_OP_INCB"],
                                AMD64_OpTypes["G_CC_OP_INCW"],
                                AMD64_OpTypes["G_CC_OP_INCL"],
                                ccall.tags,
                                signed=True,
                            )
                        elif op_v in {
                            AMD64_OpTypes["G_CC_OP_DECB"],
                            AMD64_OpTypes["G_CC_OP_DECW"],
                            AMD64_OpTypes["G_CC_OP_DECL"],
                            AMD64_OpTypes["G_CC_OP_DECQ"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                AMD64_OpTypes["G_CC_OP_DECB"],
                                AMD64_OpTypes["G_CC_OP_DECW"],
                                AMD64_OpTypes["G_CC_OP_DECL"],
                                ccall.tags,
                                signed=True,
                            )
                        zero = Expr.Const(None, None, 0, dep_1.bits)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                    if op_v in {
                        AMD64_OpTypes["G_CC_OP_SBBB"],
                        AMD64_OpTypes["G_CC_OP_SBBW"],
                        AMD64_OpTypes["G_CC_OP_SBBL"],
                        AMD64_OpTypes["G_CC_OP_SBBQ"],
                    }:
                        # SBB: sign flag of result
                        _, _, _, result = self._sbb_prep(
                            dep_1,
                            dep_2,
                            ndep,
                            op_v,
                            ccall.tags,
                            signed=True,
                        )
                        zero = Expr.Const(None, None, 0, result.bits, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, expr_op, (result, zero), True, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

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

                    # CF=1 iff (dep_1 + dep_2) <u dep_1.
                    res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), False, bits=dep_1.bits, **ccall.tags)
                    cf = Expr.BinaryOp(None, "CmpLT", (res, dep_1), False, bits=1, **ccall.tags)
                    return Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)

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

                    # CF=1 iff dep_1 <u dep_2 (borrow on subtraction)
                    cf = Expr.BinaryOp(None, "CmpLT", (dep_1, dep_2), False, bits=1, **ccall.tags)
                    return Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)

                if op_v in {
                    AMD64_OpTypes["G_CC_OP_DECB"],
                    AMD64_OpTypes["G_CC_OP_DECW"],
                    AMD64_OpTypes["G_CC_OP_DECL"],
                    AMD64_OpTypes["G_CC_OP_DECQ"],
                }:
                    # DEC preserves CF from the previous operation (stored in ndep).
                    # Extract CF as (ndep & 1).
                    cf = Expr.BinaryOp(
                        None,
                        "And",
                        [ndep, Expr.Const(None, None, 1, ndep.bits)],
                        False,
                        bits=ndep.bits,
                        **ccall.tags,
                    )
                    if cf.bits != ccall.bits:
                        cf = Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)
                    return cf

        return None

    @staticmethod
    def _sbb_prep(dep_1, dep_2, ndep, op_v, tags, signed=False):
        """Prepare common SBB values: carry, recovered arg2, and result.

        VEX SBB stores: dep_1 = argL, dep_2 = argR ^ oldCF, ndep = old flags.
        Returns (dep_1_narrow, arg2, carry_narrow, result) all at narrow width.
        """
        dep_1 = AMD64CCallRewriter._fix_size(
            dep_1,
            op_v,
            AMD64_OpTypes["G_CC_OP_SBBB"],
            AMD64_OpTypes["G_CC_OP_SBBW"],
            AMD64_OpTypes["G_CC_OP_SBBL"],
            tags,
            signed=signed,
        )
        dep_2 = AMD64CCallRewriter._fix_size(
            dep_2,
            op_v,
            AMD64_OpTypes["G_CC_OP_SBBB"],
            AMD64_OpTypes["G_CC_OP_SBBW"],
            AMD64_OpTypes["G_CC_OP_SBBL"],
            tags,
        )
        carry = Expr.BinaryOp(None, "And", [ndep, Expr.Const(None, None, 1, ndep.bits)], False, bits=ndep.bits, **tags)
        carry_narrow = (
            Expr.Convert(None, carry.bits, dep_1.bits, False, carry, **tags) if carry.bits != dep_1.bits else carry
        )
        arg2 = Expr.BinaryOp(None, "Xor", (dep_2, carry_narrow), False, bits=dep_1.bits, **tags)
        result = Expr.BinaryOp(
            None,
            "Sub",
            (dep_1, Expr.BinaryOp(None, "Add", (arg2, carry_narrow), False, bits=dep_1.bits, **tags)),
            False,
            bits=dep_1.bits,
            **tags,
        )
        return dep_1, arg2, carry_narrow, result

    @staticmethod
    def _fix_size(expr, op_v: int, type_8bit, type_16bit, type_32bit, tags, signed=False):
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
                return Expr.Const(expr.idx, None, expr.value_int & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(None, 64, bits, signed, expr, **tags)
        return expr
