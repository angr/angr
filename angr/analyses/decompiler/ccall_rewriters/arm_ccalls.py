from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import (
    ARMCondEQ,
    ARMCondGE,
    ARMCondGT,
    ARMCondHI,
    ARMCondHS,
    ARMCondLE,
    ARMCondLO,
    ARMCondLS,
    ARMCondLT,
    ARMCondMI,
    ARMCondNE,
    ARMCondPL,
)
from angr.engines.vex.claripy.ccall import ARMG_CC_OP_ADD, ARMG_CC_OP_LOGIC, ARMG_CC_OP_SBB, ARMG_CC_OP_SUB

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

                if cond_v == ARMCondEQ:
                    # Triggered by: bcminfo from firmadyne_1004
                    if op_v == ARMG_CC_OP_SUB:
                        # dep_1 == dep_2 (CondEQ)
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ", (dep_1, dep_2), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v == ARMG_CC_OP_LOGIC:
                        # Triggered by: bcminfo from firmadyne_1004
                        # CondEQ is derived from the zero flag of the logic result in dep_1.
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ", (dep_1, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: libcrypt-0.9.28.so from firmadyne_1004
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        r = Expr.BinaryOp(ccall.idx, "CmpEQ", (res, zero), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                if cond_v in {ARMCondHS, ARMCondLO}:
                    # armg_calculate_flag_c
                    if op_v == ARMG_CC_OP_SBB:
                        # Carry flag for SBB depends on the incoming carry (cc_dep3):
                        # if oldC==0: C=1 iff dep_1 >u dep_2
                        # else:      C=1 iff dep_1 >=u dep_2
                        dep_3 = ccall.operands[3]
                        zero = Expr.Const(None, None, 0, dep_3.bits, **ccall.tags)
                        dep3_is_zero = Expr.BinaryOp(None, "CmpEQ", (dep_3, zero), False, bits=1, **ccall.tags)
                        c_when_zero = Expr.BinaryOp(None, "CmpGT", (dep_1, dep_2), False, bits=1, **ccall.tags)
                        c_when_one = Expr.BinaryOp(None, "CmpGE", (dep_1, dep_2), False, bits=1, **ccall.tags)
                        cf = Expr.ITE(None, dep3_is_zero, c_when_one, c_when_zero, **ccall.tags)
                        cond = cf if inv == 0 else Expr.UnaryOp(None, "Not", cf, bits=1, **ccall.tags)
                        return Expr.Convert(None, cond.bits, ccall.bits, False, cond, **ccall.tags)
                    if op_v == ARMG_CC_OP_LOGIC:
                        # Triggered by: bcminfo from firmadyne_1004
                        # CondHS/CondLO is derived from the carry flag (shifter_carry_out stored in dep_2).
                        # VEX returns dep_2 directly (not normalized to 0/1).
                        if inv == 0:
                            return dep_2
                        one = Expr.Const(None, None, 1, dep_2.bits, **ccall.tags)
                        return Expr.BinaryOp(ccall.idx, "Xor", (dep_2, one), False, **ccall.tags)
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: bcminfo from firmadyne_1004
                        # Carry for add is computed from the add result: C=1 iff (dep_1 + dep_2) <u dep_1.
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        cf = Expr.BinaryOp(None, "CmpLT", (res, dep_1), False, bits=1, **ccall.tags)
                        cond = cf if inv == 0 else Expr.UnaryOp(None, "Not", cf, bits=1, **ccall.tags)
                        return Expr.Convert(None, cond.bits, ccall.bits, False, cond, **ccall.tags)

                elif cond_v in {ARMCondMI, ARMCondPL}:
                    # armg_calculate_flag_n
                    if op_v == ARMG_CC_OP_SUB:
                        # N flag is the sign bit of (dep_1 - dep_2).
                        res = Expr.BinaryOp(None, "Sub", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)
                        cond = nf if inv == 0 else Expr.UnaryOp(None, "Not", nf, bits=1, **ccall.tags)
                        return Expr.Convert(None, cond.bits, ccall.bits, False, cond, **ccall.tags)
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: ld-uClibc-0.9.28.so from firmadyne_1004
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        r = Expr.BinaryOp(
                            ccall.idx, "CmpLT" if inv == 0 else "CmpGE", (res, zero), True, bits=1, **ccall.tags
                        )
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                elif cond_v == ARMCondLE:
                    if op_v == ARMG_CC_OP_SUB:
                        # Signed <= comparison after SUB: dep_1 <=s dep_2.
                        r = Expr.BinaryOp(ccall.idx, "CmpLE", (dep_1, dep_2), True, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: libgcc_s.so.1 from firmadyne_1004
                        # CondLE is the inverse of CondGT, computed from the add result.
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (res, zero), True, bits=1, **ccall.tags)
                        nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)

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
                        vf = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)

                        nf_eq_vf = Expr.BinaryOp(None, "CmpEQ", (nf, vf), False, bits=1, **ccall.tags)
                        gt_cond = Expr.ITE(None, zf, nf_eq_vf, Expr.Const(None, None, 0, 1, **ccall.tags), **ccall.tags)
                        le_cond = Expr.UnaryOp(None, "Not", gt_cond, bits=1, **ccall.tags)
                        return Expr.Convert(None, le_cond.bits, ccall.bits, False, le_cond, **ccall.tags)

                elif cond_v == ARMCondNE:
                    if op_v == ARMG_CC_OP_SUB:
                        # dep_1 != dep_2,
                        #   and then negate the result if inv == 1
                        r = Expr.BinaryOp(ccall.idx, "CmpNE", (dep_1, dep_2), False, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v in {ARMCondHI, ARMCondLS}:
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: ld-uClibc-0.9.28.so (CondHI), bcm5081 (CondLS) from firmadyne_1004
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (res, zero), True, bits=1, **ccall.tags)
                        cf = Expr.BinaryOp(None, "CmpLT", (res, dep_1), False, bits=1, **ccall.tags)
                        hi = Expr.BinaryOp(
                            None,
                            "And",
                            (cf, Expr.UnaryOp(None, "Not", zf, bits=1, **ccall.tags)),
                            False,
                            bits=1,
                            **ccall.tags,
                        )
                        cond = hi if inv == 0 else Expr.UnaryOp(None, "Not", hi, bits=1, **ccall.tags)
                        return Expr.Convert(None, cond.bits, ccall.bits, False, cond, **ccall.tags)

                elif cond_v in {ARMCondGE, ARMCondLT}:
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: ld-uClibc-0.9.28.so from firmadyne_1004
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)

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
                        vf = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)

                        expr_op = "CmpEQ" if inv == 0 else "CmpNE"
                        r = Expr.BinaryOp(ccall.idx, expr_op, (nf, vf), False, bits=1, **ccall.tags)
                        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

                elif cond_v in {ARMCondGT, ARMCondLE}:
                    if op_v == ARMG_CC_OP_ADD:
                        # Triggered by: libgcc_s.so.1 (CondLE) from firmadyne_1004
                        res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
                        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
                        zf = Expr.BinaryOp(None, "CmpEQ", (res, zero), True, bits=1, **ccall.tags)
                        nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)

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
                        vf = Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **ccall.tags), **ccall.tags)

                        nf_eq_vf = Expr.BinaryOp(None, "CmpEQ", (nf, vf), False, bits=1, **ccall.tags)
                        gt_cond = Expr.ITE(None, zf, nf_eq_vf, Expr.Const(None, None, 0, 1, **ccall.tags), **ccall.tags)
                        cond = gt_cond if inv == 0 else Expr.UnaryOp(None, "Not", gt_cond, bits=1, **ccall.tags)
                        return Expr.Convert(None, cond.bits, ccall.bits, False, cond, **ccall.tags)

        return None
