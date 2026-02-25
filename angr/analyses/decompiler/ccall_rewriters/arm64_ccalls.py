from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import (
    ARM64CondEQ,
    ARM64CondNE,
    ARM64CondCS,
    ARM64CondCC,
    ARM64CondMI,
    ARM64CondPL,
    ARM64CondVS,
    ARM64CondVC,
    ARM64CondHI,
    ARM64CondLS,
    ARM64CondGE,
    ARM64CondLT,
    ARM64CondGT,
    ARM64CondLE,
    ARM64G_CC_OP_ADD32,
    ARM64G_CC_OP_ADD64,
    ARM64G_CC_OP_SUB32,
    ARM64G_CC_OP_SUB64,
    ARM64G_CC_OP_ADC32,
    ARM64G_CC_OP_ADC64,
    ARM64G_CC_OP_SBC32,
    ARM64G_CC_OP_SBC64,
    ARM64G_CC_OP_LOGIC32,
    ARM64G_CC_OP_LOGIC64,
)

from .rewriter_base import CCallRewriterBase

_SUB_OPS = {ARM64G_CC_OP_SUB32, ARM64G_CC_OP_SUB64}
_ADD_OPS = {ARM64G_CC_OP_ADD32, ARM64G_CC_OP_ADD64}
_LOGIC_OPS = {ARM64G_CC_OP_LOGIC32, ARM64G_CC_OP_LOGIC64}
_SBC_OPS = {ARM64G_CC_OP_SBC32, ARM64G_CC_OP_SBC64}
_ADC_OPS = {ARM64G_CC_OP_ADC32, ARM64G_CC_OP_ADC64}
_32BIT_OPS = {ARM64G_CC_OP_ADD32, ARM64G_CC_OP_SUB32, ARM64G_CC_OP_ADC32, ARM64G_CC_OP_SBC32, ARM64G_CC_OP_LOGIC32}


class ARM64CCallRewriter(CCallRewriterBase):
    """
    Implements VEX ccall rewriter for AArch64 (ARM64).

    ARM64 VEX ccalls use arm64g_calculate_condition with operands (cond_n_op, dep1, dep2, dep3).
    cond_n_op encodes the condition and operation as (cond << 4) | op. The ops are width-specific
    (e.g., ADD32 vs ADD64), unlike ARM32 which has a single ADD op.

    The key difference from ARM32 is that LOGIC ops on ARM64 always set C=0 and V=0 (dep2 is
    unused / always 0), whereas ARM32 LOGIC stores the shifter carry-out in dep2.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.callee != "arm64g_calculate_condition":
            return None

        cond_n_op = ccall.operands[0]
        if not isinstance(cond_n_op, Expr.Const):
            return None

        concrete_cond_n_op = cond_n_op.value_int
        cond_v = concrete_cond_n_op >> 4
        op_v = concrete_cond_n_op & 0xF
        inv = cond_v & 1

        dep_1 = ccall.operands[1]
        dep_2 = ccall.operands[2]

        # For 32-bit ops, truncate the 64-bit VEX registers down to 32 bits so that
        # comparisons and arithmetic are performed at the correct width.
        dep_1, dep_2 = self._fix_size_pair(dep_1, dep_2, op_v, ccall.tags)

        r = self._rewrite_cond(ccall, cond_v, op_v, inv, dep_1, dep_2)
        if r is None:
            return None
        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

    def _rewrite_cond(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        # -------------------------------------------------------------------
        # CondEQ / CondNE  —  Z flag
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondEQ, ARM64CondNE}:
            return self._handle_eq_ne(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondCS / CondCC  —  C flag  (aka HS / LO — unsigned >=u / <u)
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondCS, ARM64CondCC}:
            return self._handle_cs_cc(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondMI / CondPL  —  N flag  (negative / positive-or-zero)
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondMI, ARM64CondPL}:
            return self._handle_mi_pl(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondVS / CondVC  —  V flag  (signed overflow / no overflow)
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondVS, ARM64CondVC}:
            return self._handle_vs_vc(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondHI / CondLS  —  C=1 && Z=0  /  C=0 || Z=1
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondHI, ARM64CondLS}:
            return self._handle_hi_ls(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondGE / CondLT  —  N==V  /  N!=V
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondGE, ARM64CondLT}:
            return self._handle_ge_lt(ccall, op_v, inv, dep_1, dep_2)

        # -------------------------------------------------------------------
        # CondGT / CondLE  —  Z=0 && N==V  /  Z=1 || N!=V
        # -------------------------------------------------------------------
        if cond_v in {ARM64CondGT, ARM64CondLE}:
            return self._handle_gt_le(ccall, op_v, inv, dep_1, dep_2)

        return None

    # =======================================================================
    # CondEQ / CondNE  —  Z flag
    # =======================================================================
    def _handle_eq_ne(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        cmp_op = "CmpEQ" if inv == 0 else "CmpNE"

        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP (alias of SUBS) then B.EQ / B.NE
            # Z = (dep1 - dep2) == 0  <==>  dep1 == dep2
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, dep_2), False, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.EQ / B.NE
            # Z = (dep1 + dep2) == 0
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            return Expr.BinaryOp(ccall.idx, cmp_op, (res, zero), True, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.EQ / B.NE
            # Z = (dep1 == 0)  (dep1 is the logic result)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, zero), True, bits=1, **ccall.tags)

        if op_v in _SBC_OPS:
            # Triggered by: ARM64 binary — SBCS then B.EQ / B.NE
            dep_3 = ccall.operands[3]
            dep_3 = self._fix_size_single(dep_3, op_v, ccall.tags)
            one = Expr.Const(None, None, 1, dep_3.bits, **ccall.tags)
            borrow = Expr.BinaryOp(None, "Xor", (dep_3, one), False, bits=dep_3.bits, **ccall.tags)
            res = Expr.BinaryOp(None, "Sub", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            res = Expr.BinaryOp(None, "Sub", (res, borrow), bits=dep_1.bits, **ccall.tags)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            return Expr.BinaryOp(ccall.idx, cmp_op, (res, zero), True, bits=1, **ccall.tags)

        if op_v in _ADC_OPS:
            # Triggered by: ARM64 binary — ADCS then B.EQ / B.NE
            dep_3 = ccall.operands[3]
            dep_3 = self._fix_size_single(dep_3, op_v, ccall.tags)
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            res = Expr.BinaryOp(None, "Add", (res, dep_3), bits=dep_1.bits, **ccall.tags)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            return Expr.BinaryOp(ccall.idx, cmp_op, (res, zero), True, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # CondCS / CondCC  —  C flag  (unsigned >=  /  unsigned <)
    # =======================================================================
    def _handle_cs_cc(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP then B.HS / B.LO
            # C flag of SUB on ARM64: C = (dep1 >=u dep2)
            cmp_op = "CmpGE" if inv == 0 else "CmpLT"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, dep_2), False, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.HS / B.LO
            # C flag of ADD: carry = (res <u dep1)
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            cf = Expr.BinaryOp(None, "CmpLT", (res, dep_1), False, bits=1, **ccall.tags)
            return cf if inv == 0 else Expr.UnaryOp(None, "Not", cf, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.HS / B.LO
            # C flag is always 0 for LOGIC on ARM64 (no shifter carry-out).
            # CondCS => always false (0), CondCC => always true (1).
            return Expr.Const(ccall.idx, None, inv, 1, **ccall.tags)

        if op_v in _SBC_OPS:
            # Triggered by: ARM64 binary — SBCS then B.HS / B.LO
            # C flag for SBC depends on old carry (dep3):
            #   if dep3==0 (borrow in): C = dep1 >u dep2
            #   if dep3==1 (no borrow): C = dep1 >=u dep2
            dep_3 = ccall.operands[3]
            dep_3 = self._fix_size_single(dep_3, op_v, ccall.tags)
            zero = Expr.Const(None, None, 0, dep_3.bits, **ccall.tags)
            dep3_is_zero = Expr.BinaryOp(None, "CmpEQ", (dep_3, zero), False, bits=1, **ccall.tags)
            c_when_zero = Expr.BinaryOp(None, "CmpGT", (dep_1, dep_2), False, bits=1, **ccall.tags)
            c_when_one = Expr.BinaryOp(None, "CmpGE", (dep_1, dep_2), False, bits=1, **ccall.tags)
            cf = Expr.ITE(None, dep3_is_zero, c_when_one, c_when_zero, **ccall.tags)
            return cf if inv == 0 else Expr.UnaryOp(None, "Not", cf, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # CondMI / CondPL  —  N flag  (negative / positive-or-zero)
    # =======================================================================
    @staticmethod
    def _handle_mi_pl(
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP/SUBS then B.MI / B.PL
            # N = sign bit of (dep1 - dep2)
            res = Expr.BinaryOp(None, "Sub", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)
            return nf if inv == 0 else Expr.UnaryOp(None, "Not", nf, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.MI / B.PL
            # N = sign bit of (dep1 + dep2)
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            sign_op = "CmpLT" if inv == 0 else "CmpGE"
            return Expr.BinaryOp(ccall.idx, sign_op, (res, zero), True, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.MI / B.PL
            # N = sign bit of dep1 (the logic result)
            sign_op = "CmpLT" if inv == 0 else "CmpGE"
            return Expr.BinaryOp(ccall.idx, sign_op, (dep_1, zero), True, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # CondVS / CondVC  —  V flag  (signed overflow / no overflow)
    # =======================================================================
    def _handle_vs_vc(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.VS / B.VC
            # Signed overflow for ADD: sign(dep1)==sign(dep2) && sign(res)!=sign(dep1).
            # Use the extended-width technique: sign-extend both operands to (bits+1),
            # add them, then check if the result is outside the signed range.
            vf = self._compute_add_overflow(dep_1, dep_2, ccall.tags)
            return vf if inv == 0 else Expr.UnaryOp(None, "Not", vf, bits=1, **ccall.tags)

        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP/SUBS then B.VS / B.VC
            # Signed overflow for SUB: sign(dep1)!=sign(dep2) && sign(res)!=sign(dep1).
            # Same extended-width technique but with subtraction.
            vf = self._compute_sub_overflow(dep_1, dep_2, ccall.tags)
            return vf if inv == 0 else Expr.UnaryOp(None, "Not", vf, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.VS / B.VC
            # V flag is always 0 for LOGIC on ARM64.
            # CondVS => always false (0), CondVC => always true (1).
            return Expr.Const(ccall.idx, None, inv, 1, **ccall.tags)

        return None

    # =======================================================================
    # CondHI / CondLS  —  C=1 && Z=0  /  C=0 || Z=1  (unsigned > / <=)
    # =======================================================================
    @staticmethod
    def _handle_hi_ls(
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP then B.HI / B.LS
            # For SUB: C=1 && Z=0 means dep1 >u dep2. CondLS inverts to dep1 <=u dep2.
            cmp_op = "CmpGT" if inv == 0 else "CmpLE"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, dep_2), False, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.HI / B.LS
            # C && !Z from the add result.
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
            return hi if inv == 0 else Expr.UnaryOp(None, "Not", hi, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # CondGE / CondLT  —  N==V  /  N!=V  (signed >= / <)
    # =======================================================================
    def _handle_ge_lt(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP then B.GE / B.LT
            # For SUB: N==V <==> dep1 >=s dep2.
            cmp_op = "CmpGE" if inv == 0 else "CmpLT"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, dep_2), True, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.GE / B.LT
            # N==V for the add result. Compute N and V separately.
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)
            vf = self._compute_add_overflow(dep_1, dep_2, ccall.tags)
            expr_op = "CmpEQ" if inv == 0 else "CmpNE"
            return Expr.BinaryOp(ccall.idx, expr_op, (nf, vf), False, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.GE / B.LT
            # V=0 for LOGIC, so N==V <==> N==0 <==> dep1 >= 0 (not negative).
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            cmp_op = "CmpGE" if inv == 0 else "CmpLT"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, zero), True, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # CondGT / CondLE  —  Z=0 && N==V  /  Z=1 || N!=V  (signed > / <=)
    # =======================================================================
    def _handle_gt_le(
        self,
        ccall: Expr.VEXCCallExpression,
        op_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        if op_v in _SUB_OPS:
            # Triggered by: ARM64 binary — CMP then B.GT / B.LE
            # For SUB: Z=0 && N==V <==> dep1 >s dep2. Inverted: dep1 <=s dep2.
            cmp_op = "CmpGT" if inv == 0 else "CmpLE"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, dep_2), True, bits=1, **ccall.tags)

        if op_v in _ADD_OPS:
            # Triggered by: ARM64 binary — ADDS then B.GT / B.LE
            # !Z && N==V for the add result. Build it from pieces.
            res = Expr.BinaryOp(None, "Add", (dep_1, dep_2), bits=dep_1.bits, **ccall.tags)
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            zf = Expr.BinaryOp(None, "CmpEQ", (res, zero), True, bits=1, **ccall.tags)
            nf = Expr.BinaryOp(None, "CmpLT", (res, zero), True, bits=1, **ccall.tags)
            vf = self._compute_add_overflow(dep_1, dep_2, ccall.tags)

            nf_eq_vf = Expr.BinaryOp(None, "CmpEQ", (nf, vf), False, bits=1, **ccall.tags)
            # GT = !Z && (N == V).  Use ITE: if Z then 0 else (N == V).
            gt_cond = Expr.ITE(None, zf, nf_eq_vf, Expr.Const(None, None, 0, 1, **ccall.tags), **ccall.tags)
            return gt_cond if inv == 0 else Expr.UnaryOp(None, "Not", gt_cond, bits=1, **ccall.tags)

        if op_v in _LOGIC_OPS:
            # Triggered by: ARM64 binary — ANDS / TST then B.GT / B.LE
            # V=0 for LOGIC. GT = !Z && N==0 = (dep1 != 0) && (dep1 >= 0) = dep1 >s 0.
            zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)
            cmp_op = "CmpGT" if inv == 0 else "CmpLE"
            return Expr.BinaryOp(ccall.idx, cmp_op, (dep_1, zero), True, bits=1, **ccall.tags)

        return None

    # =======================================================================
    # Helpers
    # =======================================================================

    @staticmethod
    def _compute_add_overflow(dep_1: Expr.Expression, dep_2: Expr.Expression, tags) -> Expr.Expression:
        """
        Compute the V (overflow) flag for an ADD using the extended-width technique.
        Sign-extend both operands to (bits+1), add, then check whether the result
        lies outside the signed representable range for the original width.
        """
        ext_bits = dep_1.bits + 1
        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_1, **tags)
        b_ext = Expr.Convert(None, dep_2.bits, ext_bits, True, dep_2, **tags)
        s_ext = Expr.BinaryOp(None, "Add", (a_ext, b_ext), bits=ext_bits, **tags)
        max_s = (1 << (dep_1.bits - 1)) - 1
        min_s_u = (1 << ext_bits) - (1 << (dep_1.bits - 1))
        max_c = Expr.Const(None, None, max_s, ext_bits, **tags)
        min_c = Expr.Const(None, None, min_s_u, ext_bits, **tags)
        lt = Expr.BinaryOp(None, "CmpLT", (s_ext, min_c), True, bits=1, **tags)
        gt = Expr.BinaryOp(None, "CmpGT", (s_ext, max_c), True, bits=1, **tags)
        return Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **tags), **tags)

    @staticmethod
    def _compute_sub_overflow(dep_1: Expr.Expression, dep_2: Expr.Expression, tags) -> Expr.Expression:
        """
        Compute the V (overflow) flag for a SUB using the extended-width technique.
        Sign-extend both operands to (bits+1), subtract, then check whether the result
        lies outside the signed representable range for the original width.
        """
        ext_bits = dep_1.bits + 1
        a_ext = Expr.Convert(None, dep_1.bits, ext_bits, True, dep_1, **tags)
        b_ext = Expr.Convert(None, dep_2.bits, ext_bits, True, dep_2, **tags)
        s_ext = Expr.BinaryOp(None, "Sub", (a_ext, b_ext), bits=ext_bits, **tags)
        max_s = (1 << (dep_1.bits - 1)) - 1
        min_s_u = (1 << ext_bits) - (1 << (dep_1.bits - 1))
        max_c = Expr.Const(None, None, max_s, ext_bits, **tags)
        min_c = Expr.Const(None, None, min_s_u, ext_bits, **tags)
        lt = Expr.BinaryOp(None, "CmpLT", (s_ext, min_c), True, bits=1, **tags)
        gt = Expr.BinaryOp(None, "CmpGT", (s_ext, max_c), True, bits=1, **tags)
        return Expr.ITE(None, lt, gt, Expr.Const(None, None, 1, 1, **tags), **tags)

    @staticmethod
    def _fix_size(expr: Expr.Expression, op_v: int, tags) -> tuple[Expr.Expression, int]:
        """
        For 32-bit ops, truncate 64-bit VEX values to 32 bits (matching
        arm64g_32bit_truncate_operands in the VEX helper).  Returns the
        (possibly narrowed) expression and the effective width in bits.
        """
        if op_v in _32BIT_OPS:
            bits = 32
            if expr.bits > 32:
                if isinstance(expr, Expr.Const):
                    return Expr.Const(expr.idx, None, expr.value_int & 0xFFFFFFFF, 32, **tags), bits
                return Expr.Convert(None, expr.bits, 32, False, expr, **tags), bits
            return expr, bits
        return expr, 64

    @staticmethod
    def _fix_size_single(expr: Expr.Expression, op_v: int, tags) -> Expr.Expression:
        """Truncate a single expression for 32-bit ops."""
        if op_v in _32BIT_OPS and expr.bits > 32:
            if isinstance(expr, Expr.Const):
                return Expr.Const(expr.idx, None, expr.value_int & 0xFFFFFFFF, 32, **tags)
            return Expr.Convert(None, expr.bits, 32, False, expr, **tags)
        return expr

    @staticmethod
    def _fix_size_pair(
        dep_1: Expr.Expression, dep_2: Expr.Expression, op_v: int, tags
    ) -> tuple[Expr.Expression, Expr.Expression]:
        """Truncate a pair of expressions for 32-bit ops."""
        if op_v in _32BIT_OPS:
            if dep_1.bits > 32:
                if isinstance(dep_1, Expr.Const):
                    dep_1 = Expr.Const(dep_1.idx, None, dep_1.value_int & 0xFFFFFFFF, 32, **tags)
                else:
                    dep_1 = Expr.Convert(None, dep_1.bits, 32, False, dep_1, **tags)
            if dep_2.bits > 32:
                if isinstance(dep_2, Expr.Const):
                    dep_2 = Expr.Const(dep_2.idx, None, dep_2.value_int & 0xFFFFFFFF, 32, **tags)
                else:
                    dep_2 = Expr.Convert(None, dep_2.bits, 32, False, dep_2, **tags)
        return dep_1, dep_2
