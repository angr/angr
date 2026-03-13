from __future__ import annotations

from angr.ailment import Expr

from angr.calling_conventions import SimCCUsercall
from angr.ailment.expression import Call, Convert, VirtualVariable
from angr.engines.vex.claripy.ccall import data
from angr.procedures.definitions import SIM_LIBRARIES
from .rewriter_base import CCallRewriterBase

X86_CondTypes = data["X86"]["CondTypes"]
X86_OpTypes = data["X86"]["OpTypes"]
X86_CondBitMasks = data["X86"]["CondBitMasks"]
X86_CondBitOffsets = data["X86"]["CondBitOffsets"]

X86_Win32_TIB_Funcs = {
    0x18: "NtGetCurrentTeb",
    0x30: "NtGetCurrentPeb",
}


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
            ndep = ccall.operands[4]
            if isinstance(cond, Expr.Const) and isinstance(op, Expr.Const):
                # VEX op/cond selectors are always integral enums; cast away Expr.Const's int|float union.
                cond_v = int(cond.value)
                op_v = int(op.value)
                if cond_v in {X86_CondTypes["CondLE"], X86_CondTypes["CondNLE"]}:
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <=s dep_2 (CondLE) or dep_1 >s dep_2 (CondNLE)
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

                        expr_op = "CmpLE" if cond_v == X86_CondTypes["CondLE"] else "CmpGT"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, dep_2), signed=True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # Triggered by: gawk
                        # CondLE/CondNLE is (ZF == 1) or (SF != OF), which we compute from the add result.
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        ret = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (ret, zero), True, bits=1, **ccall.tags)
                        sf = Expr.BinaryOp(None, "CmpLT", (ret, zero), True, bits=1, **ccall.tags)

                        ext_bits = dep_1.bits + 1
                        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_1, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_2, **ccall.tags)
                        s_ext = Expr.BinaryOp(None, "Add", (a_ext, b_ext), bits=ext_bits, **ccall.tags)
                        max_s = (1 << (dep_1.bits - 1)) - 1
                        min_s_u = (1 << ext_bits) - (1 << (dep_1.bits - 1))
                        max_c = Expr.Const(None, None, max_s, ext_bits, **ccall.tags)
                        min_c = Expr.Const(None, None, min_s_u, ext_bits, **ccall.tags)
                        lt = Expr.BinaryOp(None, "CmpLT", (s_ext, min_c), True, bits=1, **ccall.tags)
                        gt = Expr.BinaryOp(None, "CmpGT", (s_ext, max_c), True, bits=1, **ccall.tags)
                        of = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)

                        if cond_v == X86_CondTypes["CondLE"]:
                            sf_xor_of = Expr.BinaryOp(None, "CmpNE", (sf, of), False, bits=1, **ccall.tags)
                            le = Expr.ITE(None, zf, sf_xor_of, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)
                            return Expr.Convert(None, le.bits, ccall.bits, False, le, **ccall.tags)
                        # CondNLE: (ZF == 0) and (SF == OF)
                        sf_eq_of = Expr.BinaryOp(None, "CmpEQ", (sf, of), False, bits=1, **ccall.tags)
                        nle = Expr.ITE(None, zf, sf_eq_of, Expr.Const(None, None, 0, 1, **ccall.tags), **ccall.tags)
                        return Expr.Convert(None, nle.bits, ccall.bits, False, nle, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                        X86_OpTypes["G_CC_OP_DECB"],
                        X86_OpTypes["G_CC_OP_DECW"],
                        X86_OpTypes["G_CC_OP_DECL"],
                    }:
                        # Triggered by: procd (decl), gawk (logic)
                        if op_v in {X86_OpTypes["G_CC_OP_LOGICB"], X86_OpTypes["G_CC_OP_LOGICW"]}:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_LOGICB"], X86_OpTypes["G_CC_OP_LOGICW"], ccall.tags
                            )
                        elif op_v in {X86_OpTypes["G_CC_OP_DECB"], X86_OpTypes["G_CC_OP_DECW"]}:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_DECB"], X86_OpTypes["G_CC_OP_DECW"], ccall.tags
                            )
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

                        if op_v in {
                            X86_OpTypes["G_CC_OP_DECB"],
                            X86_OpTypes["G_CC_OP_DECW"],
                            X86_OpTypes["G_CC_OP_DECL"],
                        }:
                            # DEC: CondLE/CondNLE depends on OF. For DEC, OF=1 iff res == max_signed.
                            max_s = (1 << (dep_1.bits - 1)) - 1
                            max_c = Expr.Const(None, None, max_s, dep_1.bits, **ccall.tags)
                            zf = Expr.BinaryOp(None, "CmpEQ", (dep_1, zero), False, bits=1, **ccall.tags)
                            sf = Expr.BinaryOp(None, "CmpLT", (dep_1, zero), True, bits=1, **ccall.tags)
                            of = Expr.BinaryOp(None, "CmpEQ", (dep_1, max_c), False, bits=1, **ccall.tags)

                            if cond_v == X86_CondTypes["CondLE"]:
                                sf_xor_of = Expr.BinaryOp(None, "CmpNE", (sf, of), False, bits=1, **ccall.tags)
                                le = Expr.BinaryOp(None, "Or", (zf, sf_xor_of), False, bits=1, **ccall.tags)
                                return Expr.Convert(None, le.bits, ccall.bits, False, le, **ccall.tags)

                            # CondNLE: (ZF == 0) and (SF == OF)
                            sf_eq_of = Expr.BinaryOp(None, "CmpEQ", (sf, of), False, bits=1, **ccall.tags)
                            not_zf = Expr.UnaryOp(None, "Not", zf, bits=1, **ccall.tags)
                            nle = Expr.BinaryOp(None, "And", (not_zf, sf_eq_of), False, bits=1, **ccall.tags)
                            return Expr.Convert(None, nle.bits, ccall.bits, False, nle, **ccall.tags)

                        # LOGIC: OF=0, so CondLE/CondNLE reduces to result <=s 0 / >s 0.
                        expr_op = "CmpLE" if cond_v == X86_CondTypes["CondLE"] else "CmpGT"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), signed=True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v in {X86_CondTypes["CondO"], X86_CondTypes["CondNO"]}:
                    negate = cond_v == X86_CondTypes["CondNO"]
                    ret_cond = None
                    if op_v in {
                        X86_OpTypes["G_CC_OP_UMULB"],
                        X86_OpTypes["G_CC_OP_UMULW"],
                        X86_OpTypes["G_CC_OP_UMULL"],
                    }:
                        # Unsigned multiply: OF=CF=1 iff the product doesn't fit in nbits.
                        if op_v in {X86_OpTypes["G_CC_OP_UMULB"], X86_OpTypes["G_CC_OP_UMULW"]}:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_UMULB"], X86_OpTypes["G_CC_OP_UMULW"], ccall.tags
                            )
                            dep_2 = self._fix_size(
                                dep_2, op_v, X86_OpTypes["G_CC_OP_UMULB"], X86_OpTypes["G_CC_OP_UMULW"], ccall.tags
                            )
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        r = Call(
                            ccall.idx,
                            "__OFMUL__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # Signed overflow for add.
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        r = Call(
                            ccall.idx,
                            "__OFADD__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r
                    if op_v in {
                        X86_OpTypes["G_CC_OP_INCB"],
                        X86_OpTypes["G_CC_OP_INCW"],
                        X86_OpTypes["G_CC_OP_INCL"],
                    }:
                        # dep_1 is the result
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_INCB"], X86_OpTypes["G_CC_OP_INCW"], ccall.tags
                        )
                        overflowed = Expr.Const(
                            None,
                            None,
                            1 << (dep_1.bits - 1),
                            dep_1.bits,
                            **ccall.tags,
                        )
                        ret_cond = Expr.BinaryOp(None, "CmpEQ", (dep_1, overflowed), signed=False, bits=1, **ccall.tags)
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_ADCB"],
                        X86_OpTypes["G_CC_OP_ADCW"],
                        X86_OpTypes["G_CC_OP_ADCL"],
                    }:
                        # Triggered by: grep
                        # Signed overflow for adc: dep_1 + arg2 + old_carry
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADCB"], X86_OpTypes["G_CC_OP_ADCW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADCB"], X86_OpTypes["G_CC_OP_ADCW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_1, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, carry_ext, **ccall.tags)
                        s_ext = Expr.BinaryOp(
                            None,
                            "Add",
                            (Expr.BinaryOp(None, "Add", (a_ext, b_ext), bits=ext_bits, **ccall.tags), c_ext),
                            bits=ext_bits,
                            **ccall.tags,
                        )
                        max_s = (1 << (dep_1.bits - 1)) - 1
                        min_s_u = (1 << ext_bits) - (1 << (dep_1.bits - 1))
                        max_c = Expr.Const(None, None, max_s, ext_bits, **ccall.tags)
                        min_c = Expr.Const(None, None, min_s_u, ext_bits, **ccall.tags)
                        lt = Expr.BinaryOp(None, "CmpLT", (s_ext, min_c), True, bits=1, **ccall.tags)
                        gt = Expr.BinaryOp(None, "CmpGT", (s_ext, max_c), True, bits=1, **ccall.tags)
                        ret_cond = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)
                    elif op_v in {
                        X86_OpTypes["G_CC_OP_SBBB"],
                        X86_OpTypes["G_CC_OP_SBBW"],
                        X86_OpTypes["G_CC_OP_SBBL"],
                    }:
                        # Triggered by: grep
                        # Signed overflow for sbb: dep_1 - arg2 - old_carry
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_1, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, carry_ext, **ccall.tags)
                        d_ext = Expr.BinaryOp(
                            None,
                            "Sub",
                            (Expr.BinaryOp(None, "Sub", (a_ext, b_ext), bits=ext_bits, **ccall.tags), c_ext),
                            bits=ext_bits,
                            **ccall.tags,
                        )
                        max_s = (1 << (dep_1.bits - 1)) - 1
                        min_s_u = (1 << ext_bits) - (1 << (dep_1.bits - 1))
                        max_c = Expr.Const(None, None, max_s, ext_bits, **ccall.tags)
                        min_c = Expr.Const(None, None, min_s_u, ext_bits, **ccall.tags)
                        lt = Expr.BinaryOp(None, "CmpLT", (d_ext, min_c), True, bits=1, **ccall.tags)
                        gt = Expr.BinaryOp(None, "CmpGT", (d_ext, max_c), True, bits=1, **ccall.tags)
                        ret_cond = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)
                    elif op_v == X86_OpTypes["G_CC_OP_SMULL"]:
                        # Triggered by: gawk
                        # Signed multiplication overflow if product does not fit in signed 32-bit.
                        cc = SimCCUsercall(self.project.arch, [], None) if self.project else None
                        r = Call(
                            ccall.idx,
                            "__OFMUL__",
                            calling_convention=cc,
                            args=[dep_1, dep_2],
                            bits=ccall.bits,
                            **ccall.tags,
                        )
                        if negate:
                            r = Expr.UnaryOp(None, "Not", r, bits=ccall.bits, **ccall.tags)
                        return r

                    if ret_cond is not None:
                        false_val = 1 if negate else 0
                        true_val = 0 if negate else 1
                        return Expr.ITE(
                            ccall.idx,
                            ret_cond,
                            Expr.Const(None, None, false_val, ccall.bits, **ccall.tags),
                            Expr.Const(None, None, true_val, ccall.bits, **ccall.tags),
                            **ccall.tags,
                        )
                elif cond_v in {X86_CondTypes["CondZ"], X86_CondTypes["CondNZ"]}:
                    expr_op = "CmpEQ" if cond_v == X86_CondTypes["CondZ"] else "CmpNE"
                    op_v = int(op.value)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # dep_1 + dep_2 == 0 (CondZ) or dep_1 + dep_2 != 0 (CondNZ)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
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
                            expr_op,
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
                        # dep_1 - dep_2 == 0 (CondZ) or dep_1 - dep_2 != 0 (CondNZ)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            expr_op,
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
                        # dep_1 == 0 (CondZ) or dep_1 != 0 (CondNZ)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_LOGICB"], X86_OpTypes["G_CC_OP_LOGICW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            expr_op,
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            True,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v == X86_OpTypes["G_CC_OP_COPY"]:
                        # Triggered by: grep
                        # dep_1 & G_CC_MASK_Z != 0 (CondZ) or == 0 (CondNZ)
                        bitmask = X86_CondBitMasks["G_CC_MASK_Z"]
                        assert isinstance(bitmask, int)
                        flag = Expr.Const(None, None, bitmask, dep_1.bits, **ccall.tags)
                        masked = Expr.BinaryOp(None, "And", [dep_1, flag], False, bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        z_expr_op = "CmpNE" if cond_v == X86_CondTypes["CondZ"] else "CmpEQ"
                        cmp = Expr.BinaryOp(ccall.idx, z_expr_op, (masked, zero), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_INCB"],
                        X86_OpTypes["G_CC_OP_INCW"],
                        X86_OpTypes["G_CC_OP_INCL"],
                        X86_OpTypes["G_CC_OP_DECB"],
                        X86_OpTypes["G_CC_OP_DECW"],
                        X86_OpTypes["G_CC_OP_DECL"],
                    }:
                        # Triggered by: ls
                        # dep_1 is the result for inc/dec ops
                        if op_v in {
                            X86_OpTypes["G_CC_OP_INCB"],
                            X86_OpTypes["G_CC_OP_INCW"],
                            X86_OpTypes["G_CC_OP_INCL"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_INCB"], X86_OpTypes["G_CC_OP_INCW"], ccall.tags
                            )
                        elif op_v in {
                            X86_OpTypes["G_CC_OP_DECB"],
                            X86_OpTypes["G_CC_OP_DECW"],
                            X86_OpTypes["G_CC_OP_DECL"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_DECB"], X86_OpTypes["G_CC_OP_DECW"], ccall.tags
                            )
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SHLB"],
                        X86_OpTypes["G_CC_OP_SHLW"],
                        X86_OpTypes["G_CC_OP_SHLL"],
                        X86_OpTypes["G_CC_OP_SHRB"],
                        X86_OpTypes["G_CC_OP_SHRW"],
                        X86_OpTypes["G_CC_OP_SHRL"],
                    }:
                        # Triggered by: gawk
                        # dep_1 is the result for shift ops
                        if op_v in {
                            X86_OpTypes["G_CC_OP_SHLB"],
                            X86_OpTypes["G_CC_OP_SHLW"],
                            X86_OpTypes["G_CC_OP_SHLL"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_SHLB"], X86_OpTypes["G_CC_OP_SHLW"], ccall.tags
                            )
                        else:
                            dep_1 = self._fix_size(
                                dep_1, op_v, X86_OpTypes["G_CC_OP_SHRB"], X86_OpTypes["G_CC_OP_SHRW"], ccall.tags
                            )
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v in {X86_CondTypes["CondL"], X86_CondTypes["CondNL"]}:
                    expr_op = "CmpLT" if cond_v == X86_CondTypes["CondL"] else "CmpGE"
                    op_v = int(op.value)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 - dep_2 < 0 (CondL) or dep_1 - dep_2 >= 0 (CondNL)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            expr_op,
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
                        # dep_1 < 0 (CondL) or dep_1 >= 0 (CondNL)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_LOGICB"], X86_OpTypes["G_CC_OP_LOGICW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            expr_op,
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            True,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SBBB"],
                        X86_OpTypes["G_CC_OP_SBBW"],
                        X86_OpTypes["G_CC_OP_SBBL"],
                    }:
                        # Triggered by: grep
                        # For sbb ops, DEP2 encodes (arg2 XOR old_carry) and NDEP encodes old_carry.
                        # VEX computes OF = ((dep1 ^ arg2) & (dep1 ^ res))[MSB], SF = res[MSB].
                        # CondL = SF != OF, CondNL = SF == OF.
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        # res = dep1 - arg2 - carry
                        sub1 = Expr.BinaryOp(None, "Sub", (dep_1, arg2), bits=dep_1.bits, **ccall.tags)
                        res = Expr.BinaryOp(None, "Sub", (sub1, carry_ext), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        sf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)
                        # OF = ((dep1 ^ arg2) & (dep1 ^ res))[MSB]
                        xor1 = Expr.BinaryOp(None, "Xor", (dep_1, arg2), bits=dep_1.bits, **ccall.tags)
                        xor2 = Expr.BinaryOp(None, "Xor", (dep_1, res), bits=dep_1.bits, **ccall.tags)
                        of_full = Expr.BinaryOp(None, "And", (xor1, xor2), bits=dep_1.bits, **ccall.tags)
                        of = Expr.BinaryOp(None, "CmpLT", (of_full, zero), True, bits=1, **ccall.tags)
                        sf_of_op = "CmpNE" if cond_v == X86_CondTypes["CondL"] else "CmpEQ"
                        cmp = Expr.BinaryOp(ccall.idx, sf_of_op, (sf, of), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v in {
                    X86_CondTypes["CondBE"],
                    X86_CondTypes["CondB"],
                }:
                    op_v = int(op.value)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # ADD: CondB is CF, CondBE is (CF|ZF).
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADDB"], X86_OpTypes["G_CC_OP_ADDW"], ccall.tags
                        )
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        cf = Expr.BinaryOp(None, "CmpLT", (res, dep_1), False, bits=1, **ccall.tags)
                        if cond_v == X86_CondTypes["CondB"]:
                            return Expr.Convert(None, cf.bits, ccall.bits, False, cf, **ccall.tags)

                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (res, zero), False, bits=1, **ccall.tags)
                        be = Expr.BinaryOp(None, "Or", (cf, zf), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, be.bits, ccall.bits, False, be, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # dep_1 <= dep_2  if CondBE
                        # dep_1 < dep_2   if CondB
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, dep_2),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                    }:
                        # dep_1 <= 0  if CondBE
                        # dep_1 < 0   if CondB
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_LOGICB"], X86_OpTypes["G_CC_OP_LOGICW"], ccall.tags
                        )
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (dep_1, Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SBBB"],
                        X86_OpTypes["G_CC_OP_SBBW"],
                        X86_OpTypes["G_CC_OP_SBBL"],
                    }:
                        # Triggered by: grep
                        # Borrow flag for sbb: a <u (arg2 + old_carry)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        # compute in a wider bit-width to preserve carry-out of (arg2 + carry)
                        ext_bits = dep_1.bits + 1
                        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, dep_1, **ccall.tags)
                        b_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, arg2, **ccall.tags)
                        c_ext = Expr.Convert(None, dep_1.bits, ext_bits, False, carry_ext, **ccall.tags)
                        rhs_ext = Expr.BinaryOp(None, "Add", (b_ext, c_ext), bits=ext_bits, **ccall.tags)
                        cmp = Expr.BinaryOp(
                            ccall.idx,
                            "CmpLE" if cond_v == X86_CondTypes["CondBE"] else "CmpLT",
                            (a_ext, rhs_ext),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if (
                        op_v
                        in {
                            X86_OpTypes["G_CC_OP_ADCB"],
                            X86_OpTypes["G_CC_OP_ADCW"],
                            X86_OpTypes["G_CC_OP_ADCL"],
                        }
                        and cond_v == X86_CondTypes["CondB"]
                    ):
                        # Triggered by: grep
                        # Carry-out of dep_1 + arg2 + old_carry
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_ADCB"], X86_OpTypes["G_CC_OP_ADCW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_ADCB"], X86_OpTypes["G_CC_OP_ADCW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        s_ext = Expr.BinaryOp(
                            None,
                            "Add",
                            (Expr.BinaryOp(None, "Add", (a_ext, b_ext), bits=ext_bits, **ccall.tags), c_ext),
                            bits=ext_bits,
                            **ccall.tags,
                        )
                        carry_flag = Expr.Const(None, None, 1 << dep_1.bits, ext_bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, "CmpGE", (s_ext, carry_flag), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v in {X86_CondTypes["CondNB"], X86_CondTypes["CondNBE"]}:
                    op_v = int(op.value)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SBBB"],
                        X86_OpTypes["G_CC_OP_SBBW"],
                        X86_OpTypes["G_CC_OP_SBBL"],
                    }:
                        # Triggered by: grep
                        # No-borrow flag for sbb: a >=u (arg2 + old_carry)
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SBBB"], X86_OpTypes["G_CC_OP_SBBW"], ccall.tags
                        )
                        carry = Expr.BinaryOp(
                            None,
                            "And",
                            [ndep, Expr.Const(None, None, 1, ndep.bits, **ccall.tags)],
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
                        expr_op = "CmpGE" if cond_v == X86_CondTypes["CondNB"] else "CmpGT"
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (a_ext, rhs_ext), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # Triggered by: grep
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        expr_op = "CmpGE" if cond_v == X86_CondTypes["CondNB"] else "CmpGT"
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, dep_2), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                elif cond_v in {X86_CondTypes["CondS"], X86_CondTypes["CondNS"]}:
                    # Triggered by: mIRC 7.43 (mirc-7-43.exe), Winamp 5.622 (winamp.exe)
                    expr_op = "CmpLT" if cond_v == X86_CondTypes["CondS"] else "CmpGE"
                    op_v = int(op.value)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_ADDB"],
                        X86_OpTypes["G_CC_OP_ADDW"],
                        X86_OpTypes["G_CC_OP_ADDL"],
                    }:
                        # SF is the sign bit of dep_1 + dep_2.
                        dep_1 = self._fix_size(
                            dep_1,
                            op_v,
                            X86_OpTypes["G_CC_OP_ADDB"],
                            X86_OpTypes["G_CC_OP_ADDW"],
                            ccall.tags,
                        )
                        dep_2 = self._fix_size(
                            dep_2,
                            op_v,
                            X86_OpTypes["G_CC_OP_ADDB"],
                            X86_OpTypes["G_CC_OP_ADDW"],
                            ccall.tags,
                        )
                        ret = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (ret, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_LOGICB"],
                        X86_OpTypes["G_CC_OP_LOGICW"],
                        X86_OpTypes["G_CC_OP_LOGICL"],
                        X86_OpTypes["G_CC_OP_SHRB"],
                        X86_OpTypes["G_CC_OP_SHRW"],
                        X86_OpTypes["G_CC_OP_SHRL"],
                    }:
                        # SF is the sign bit of dep_1 (the result for logic/shift ops).
                        if op_v in {
                            X86_OpTypes["G_CC_OP_LOGICB"],
                            X86_OpTypes["G_CC_OP_LOGICW"],
                            X86_OpTypes["G_CC_OP_LOGICL"],
                        }:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                X86_OpTypes["G_CC_OP_LOGICB"],
                                X86_OpTypes["G_CC_OP_LOGICW"],
                                ccall.tags,
                            )
                        else:
                            dep_1 = self._fix_size(
                                dep_1,
                                op_v,
                                X86_OpTypes["G_CC_OP_SHRB"],
                                X86_OpTypes["G_CC_OP_SHRW"],
                                ccall.tags,
                            )
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SUBB"],
                        X86_OpTypes["G_CC_OP_SUBW"],
                        X86_OpTypes["G_CC_OP_SUBL"],
                    }:
                        # Triggered by: tar
                        # SF is the sign bit of dep_1 - dep_2.
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        dep_2 = self._fix_size(
                            dep_2, op_v, X86_OpTypes["G_CC_OP_SUBB"], X86_OpTypes["G_CC_OP_SUBW"], ccall.tags
                        )
                        ret = Expr.BinaryOp(None, "Sub", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (ret, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
                    if op_v in {
                        X86_OpTypes["G_CC_OP_SHLB"],
                        X86_OpTypes["G_CC_OP_SHLW"],
                        X86_OpTypes["G_CC_OP_SHLL"],
                    }:
                        # Triggered by: gawk
                        # SF is the sign bit of dep_1 (the result for shift ops).
                        dep_1 = self._fix_size(
                            dep_1, op_v, X86_OpTypes["G_CC_OP_SHLB"], X86_OpTypes["G_CC_OP_SHLW"], ccall.tags
                        )
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        cmp = Expr.BinaryOp(ccall.idx, expr_op, (dep_1, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, cmp.bits, ccall.bits, False, cmp, **ccall.tags)
        elif ccall.callee == "x86g_use_seg_selector":
            seg_selector = ccall.operands[2]
            virtual_addr = ccall.operands[3]
            while isinstance(seg_selector, Convert):
                seg_selector = seg_selector.operands[0]
            if (
                self.project.simos.name == "Win32"
                and isinstance(seg_selector, VirtualVariable)
                and seg_selector.was_reg
                and self.project.arch.register_names.get(seg_selector.reg_offset, "") == "fs"
                and isinstance(virtual_addr, Expr.Const)
                and virtual_addr.value_int in X86_Win32_TIB_Funcs
            ):
                accessor_name = X86_Win32_TIB_Funcs[virtual_addr.value_int]
                prototype = SIM_LIBRARIES["ntdll.dll"][0].get_prototype(accessor_name, deref=True)
                returnty_bits = ccall.bits
                if prototype is not None:
                    prototype = prototype.with_arch(self.project.arch)
                    if prototype.returnty and prototype.returnty.size:
                        returnty_bits = prototype.returnty.size
                call_expr = Call(
                    ccall.idx,
                    X86_Win32_TIB_Funcs[virtual_addr.value_int],
                    args=[],
                    prototype=prototype,
                    bits=returnty_bits,
                    **ccall.tags,
                )
                call_expr.tags["is_prototype_guessed"] = False
                ref_expr = Expr.UnaryOp(None, "Reference", call_expr, **ccall.tags)
                if returnty_bits == ccall.bits:
                    return ref_expr
                return Expr.Convert(None, returnty_bits, ccall.bits, False, ref_expr, **ccall.tags)
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
                return Expr.Const(expr.idx, None, expr.value_int & ((1 << bits) - 1), bits, **tags)
            return Expr.Convert(None, 32, bits, False, expr, **tags)
        return expr
