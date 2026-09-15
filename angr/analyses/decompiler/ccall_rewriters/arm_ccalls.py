from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import (
    ARMG_CC_OP_ADC,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_COPY,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_MUL,
    ARMG_CC_OP_MULL,
    ARMG_CC_OP_NUMBER,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
    ARMG_CC_SHIFT_C,
    ARMG_CC_SHIFT_N,
    ARMG_CC_SHIFT_V,
    ARMG_CC_SHIFT_Z,
    ARMCondAL,
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
    ARMCondNV,
    ARMCondPL,
    ARMCondVC,
    ARMCondVS,
)

from .rewriter_base import CCallRewriterBase

_FLAG_CALLEES = {
    "armg_calculate_flag_c": "c",
    "armg_calculate_flag_n": "n",
    "armg_calculate_flag_z": "z",
    "armg_calculate_flag_v": "v",
}

# condition code -> (comparison, signed) for flags computed from ``dep_1 - dep_2``
_SUB_CMP_OPS: dict[int, tuple[str, bool]] = {
    ARMCondEQ: ("CmpEQ", False),
    ARMCondNE: ("CmpNE", False),
    ARMCondHS: ("CmpGE", False),
    ARMCondLO: ("CmpLT", False),
    ARMCondHI: ("CmpGT", False),
    ARMCondLS: ("CmpLE", False),
    ARMCondGE: ("CmpGE", True),
    ARMCondLT: ("CmpLT", True),
    ARMCondGT: ("CmpGT", True),
    ARMCondLE: ("CmpLE", True),
}
_UNSIGNED_CONDS = {ARMCondHS, ARMCondLO, ARMCondHI, ARMCondLS}
_SIGNED_CONDS = {ARMCondGE, ARMCondLT, ARMCondGT, ARMCondLE}

_MASK32 = 0xFFFF_FFFF


class ARMCCallRewriter(CCallRewriterBase):
    """
    Rewrites ARM flag helpers following libVEX's guest_arm_helpers.c. ``cond_n_op`` packs the condition code in bits
    7:4 and the cc_op in bits 3:0; odd condition codes negate their even partner.

    Flag semantics per cc_op (dep_1, dep_2, dep_3):

    COPY:   NZCV in bits 31:28 of dep_1
    ADD:    res = dep_1 + dep_2;              C = res <u dep_1
    SUB:    res = dep_1 - dep_2;              C = dep_1 >=u dep_2
    ADC:    res = dep_1 + dep_2 + dep_3;      C = res <=u dep_1 if dep_3 else res <u dep_1
    SBB:    res = dep_1 - dep_2 - (dep_3^1);  C = dep_1 >=u dep_2 if dep_3 else dep_1 >u dep_2
    LOGIC:  res = dep_1;  C = dep_2 (shifter carry out);  V = dep_3 (old V)
    MUL:    res = dep_1;  C = dep_3[1];  V = dep_3[0]
    MULL:   res = dep_2:dep_1;  C = dep_3[1];  V = dep_3[0]

    ADC with dep_3 == 0 is ADD and SBB with dep_3 == 1 is SUB. Only shapes that map exactly onto AIL expressions are
    rewritten; everything else is left alone.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if len(ccall.operands) != 4 or ccall.bits != 32 or any(o.bits != 32 for o in ccall.operands):
            return None
        callee = self._original_callee(ccall)
        if callee == "armg_calculate_condition":
            return self._rewrite_condition(ccall)
        if callee in _FLAG_CALLEES:
            cc_op = ccall.operands[0]
            if not isinstance(cc_op, Expr.Const):
                return None
            r = self._flag(ccall, _FLAG_CALLEES[callee], cc_op.value_int, *ccall.operands[1:])
            return None if r is None else self._wrap(ccall, r)
        return None

    # ---- armg_calculate_condition ----

    def _rewrite_condition(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        cond_n_op = ccall.operands[0]
        if not isinstance(cond_n_op, Expr.Const):
            return None
        cond = (cond_n_op.value_int >> 4) & 0xF
        op = cond_n_op.value_int & 0xF
        if cond == ARMCondAL:
            return Expr.Const(ccall.idx, 1, ccall.bits, **ccall.tags)
        if cond == ARMCondNV:
            return Expr.Const(ccall.idx, 0, ccall.bits, **ccall.tags)
        if op >= ARMG_CC_OP_NUMBER:
            return None
        r = self._condition(ccall, cond, op, *ccall.operands[1:])
        return None if r is None else self._wrap(ccall, r)

    def _condition(
        self,
        ccall: Expr.VEXCCallExpression,
        cond: int,
        op: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        dep_3: Expr.Expression,
    ) -> Expr.Expression | None:
        op = self._normalize_op(op, dep_3)
        if op == ARMG_CC_OP_SUB:
            return self._cond_sub(ccall, cond, dep_1, dep_2)
        if op == ARMG_CC_OP_ADD:
            return self._cond_add(ccall, cond, dep_1, dep_2)
        if op == ARMG_CC_OP_SBB and self._is_const(dep_3, 0):
            r = self._cond_sub_borrow(ccall, cond, dep_1, dep_2)
            if r is not None:
                return r
        if op in {ARMG_CC_OP_ADC, ARMG_CC_OP_SBB}:
            return self._cond_carry_result(ccall, cond, op, dep_1, dep_2, dep_3)
        if op in {ARMG_CC_OP_LOGIC, ARMG_CC_OP_MUL}:
            return self._cond_logic(ccall, cond, op, dep_1, dep_2)
        if op == ARMG_CC_OP_COPY:
            return self._cond_copy(ccall, cond, dep_1)
        return None

    def _cond_sub(
        self, ccall: Expr.VEXCCallExpression, cond: int, dep_1: Expr.Expression, dep_2: Expr.Expression
    ) -> Expr.Expression | None:
        if cond in _SUB_CMP_OPS:
            cmp_op, signed = _SUB_CMP_OPS[cond]
            return self._cmp(ccall, cmp_op, dep_1, dep_2, signed)
        if cond in {ARMCondMI, ARMCondPL}:
            # N is the sign of the (wrapped) difference, not the signed comparison
            res = dep_1 if self._is_const(dep_2, 0) else self._binop(ccall, "Sub", dep_1, dep_2)
            return self._cmp(ccall, "CmpLT" if cond == ARMCondMI else "CmpGE", res, self._const(ccall, 0), True)
        return None

    def _cond_add(
        self, ccall: Expr.VEXCCallExpression, cond: int, dep_1: Expr.Expression, dep_2: Expr.Expression
    ) -> Expr.Expression | None:
        if isinstance(dep_2, Expr.Const) and cond in _SUB_CMP_OPS:
            # dep_1 + c compares like dep_1 - (-c); unsigned conditions need c != 0 (no carry is possible), signed
            # ones need -c to be representable
            c = dep_2.value_int & _MASK32
            if (
                cond in {ARMCondEQ, ARMCondNE}
                or (cond in _UNSIGNED_CONDS and c != 0)
                or (cond in _SIGNED_CONDS and c != 0x8000_0000)
            ):
                cmp_op, signed = _SUB_CMP_OPS[cond]
                return self._cmp(ccall, cmp_op, dep_1, self._const(ccall, (-c) & _MASK32), signed)
            return None

        res = self._binop(ccall, "Add", dep_1, dep_2)
        zero = self._const(ccall, 0)
        if cond in {ARMCondEQ, ARMCondNE}:
            return self._cmp(ccall, "CmpEQ" if cond == ARMCondEQ else "CmpNE", res, zero, False)
        if cond in {ARMCondMI, ARMCondPL}:
            return self._cmp(ccall, "CmpLT" if cond == ARMCondMI else "CmpGE", res, zero, True)
        if cond in {ARMCondHS, ARMCondLO}:
            return self._cmp(ccall, "CmpLT" if cond == ARMCondHS else "CmpGE", res, dep_1, False)
        if cond == ARMCondHI:
            return self._logical(
                ccall, "LogicalAnd", self._cmp(ccall, "CmpLT", res, dep_1, False), self._cmp(ccall, "CmpNE", res, zero)
            )
        if cond == ARMCondLS:
            return self._logical(
                ccall, "LogicalOr", self._cmp(ccall, "CmpGE", res, dep_1, False), self._cmp(ccall, "CmpEQ", res, zero)
            )
        return None

    def _cond_sub_borrow(
        self, ccall: Expr.VEXCCallExpression, cond: int, dep_1: Expr.Expression, dep_2: Expr.Expression
    ) -> Expr.Expression | None:
        # res = dep_1 - dep_2 - 1
        if cond in {ARMCondHS, ARMCondLO}:
            return self._cmp(ccall, "CmpGT" if cond == ARMCondHS else "CmpLE", dep_1, dep_2, False)
        if cond in {ARMCondEQ, ARMCondNE}:
            rhs = self._binop(ccall, "Add", dep_2, self._const(ccall, 1))
            return self._cmp(ccall, "CmpEQ" if cond == ARMCondEQ else "CmpNE", dep_1, rhs)
        return None

    def _cond_carry_result(
        self,
        ccall: Expr.VEXCCallExpression,
        cond: int,
        op: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        dep_3: Expr.Expression,
    ) -> Expr.Expression | None:
        # Z and N of ADC/SBB only depend on the result, whatever the incoming carry is
        res = self._carry_result(ccall, op, dep_1, dep_2, dep_3)
        zero = self._const(ccall, 0)
        if cond in {ARMCondEQ, ARMCondNE}:
            return self._cmp(ccall, "CmpEQ" if cond == ARMCondEQ else "CmpNE", res, zero)
        if cond in {ARMCondMI, ARMCondPL}:
            return self._cmp(ccall, "CmpLT" if cond == ARMCondMI else "CmpGE", res, zero, True)
        return None

    def _cond_logic(
        self, ccall: Expr.VEXCCallExpression, cond: int, op: int, res: Expr.Expression, shco: Expr.Expression
    ) -> Expr.Expression | None:
        zero = self._const(ccall, 0)
        if cond in {ARMCondEQ, ARMCondNE}:
            return self._cmp(ccall, "CmpEQ" if cond == ARMCondEQ else "CmpNE", res, zero)
        if cond in {ARMCondMI, ARMCondPL}:
            return self._cmp(ccall, "CmpLT" if cond == ARMCondMI else "CmpGE", res, zero, True)
        if op == ARMG_CC_OP_LOGIC:
            if cond in {ARMCondHS, ARMCondLO}:
                return self._is_nonzero(ccall, shco, cond == ARMCondHS)
            if cond == ARMCondHI:
                return self._logical(
                    ccall, "LogicalAnd", self._is_nonzero(ccall, shco, True), self._cmp(ccall, "CmpNE", res, zero)
                )
            if cond == ARMCondLS:
                return self._logical(
                    ccall, "LogicalOr", self._is_nonzero(ccall, shco, False), self._cmp(ccall, "CmpEQ", res, zero)
                )
        return None

    def _cond_copy(self, ccall: Expr.VEXCCallExpression, cond: int, nzcv: Expr.Expression) -> Expr.Expression | None:
        def flag(shift: int, is_set: bool) -> Expr.Expression:
            return self._is_nonzero(ccall, self._binop(ccall, "And", nzcv, self._const(ccall, 1 << shift)), is_set)

        if cond in {ARMCondEQ, ARMCondNE}:
            return flag(ARMG_CC_SHIFT_Z, cond == ARMCondEQ)
        if cond in {ARMCondHS, ARMCondLO}:
            return flag(ARMG_CC_SHIFT_C, cond == ARMCondHS)
        if cond in {ARMCondMI, ARMCondPL}:
            return flag(ARMG_CC_SHIFT_N, cond == ARMCondMI)
        if cond in {ARMCondVS, ARMCondVC}:
            return flag(ARMG_CC_SHIFT_V, cond == ARMCondVS)
        if cond == ARMCondHI:
            return self._logical(ccall, "LogicalAnd", flag(ARMG_CC_SHIFT_C, True), flag(ARMG_CC_SHIFT_Z, False))
        if cond == ARMCondLS:
            return self._logical(ccall, "LogicalOr", flag(ARMG_CC_SHIFT_C, False), flag(ARMG_CC_SHIFT_Z, True))
        # N != V: bit 31 xor bit 28
        n_xor_v = self._binop(
            ccall,
            "And",
            self._binop(ccall, "Xor", self._shr(ccall, nzcv, ARMG_CC_SHIFT_N - ARMG_CC_SHIFT_V), nzcv),
            self._const(ccall, 1 << ARMG_CC_SHIFT_V),
        )
        if cond in {ARMCondGE, ARMCondLT}:
            return self._is_nonzero(ccall, n_xor_v, cond == ARMCondLT)
        if cond == ARMCondGT:
            return self._logical(
                ccall, "LogicalAnd", flag(ARMG_CC_SHIFT_Z, False), self._is_nonzero(ccall, n_xor_v, False)
            )
        if cond == ARMCondLE:
            return self._logical(
                ccall, "LogicalOr", flag(ARMG_CC_SHIFT_Z, True), self._is_nonzero(ccall, n_xor_v, True)
            )
        return None

    # ---- armg_calculate_flag_{c,n,z,v} ----

    def _flag(
        self,
        ccall: Expr.VEXCCallExpression,
        flag: str,
        op: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        dep_3: Expr.Expression,
    ) -> Expr.Expression | None:
        op = self._normalize_op(op, dep_3)
        zero = self._const(ccall, 0)
        one = self._const(ccall, 1)

        if flag == "c":
            if op == ARMG_CC_OP_SUB:
                return self._cmp(ccall, "CmpGE", dep_1, dep_2, False)
            if op == ARMG_CC_OP_ADD:
                return self._cmp(ccall, "CmpLT", self._binop(ccall, "Add", dep_1, dep_2), dep_1, False)
            if op == ARMG_CC_OP_SBB and self._is_const(dep_3, 0):
                return self._cmp(ccall, "CmpGT", dep_1, dep_2, False)
            if op == ARMG_CC_OP_LOGIC:
                return dep_2
            if op in {ARMG_CC_OP_MUL, ARMG_CC_OP_MULL}:
                return self._binop(ccall, "And", self._shr(ccall, dep_3, 1), one)
            if op == ARMG_CC_OP_COPY:
                return self._binop(ccall, "And", self._shr(ccall, dep_1, ARMG_CC_SHIFT_C), one)
            return None

        if flag == "n":
            if op == ARMG_CC_OP_SUB:
                res = dep_1 if self._is_const(dep_2, 0) else self._binop(ccall, "Sub", dep_1, dep_2)
                return self._cmp(ccall, "CmpLT", res, zero, True)
            if op == ARMG_CC_OP_ADD:
                return self._cmp(ccall, "CmpLT", self._binop(ccall, "Add", dep_1, dep_2), zero, True)
            if op in {ARMG_CC_OP_ADC, ARMG_CC_OP_SBB}:
                return self._cmp(ccall, "CmpLT", self._carry_result(ccall, op, dep_1, dep_2, dep_3), zero, True)
            if op in {ARMG_CC_OP_LOGIC, ARMG_CC_OP_MUL}:
                return self._cmp(ccall, "CmpLT", dep_1, zero, True)
            if op == ARMG_CC_OP_MULL:
                return self._cmp(ccall, "CmpLT", dep_2, zero, True)
            if op == ARMG_CC_OP_COPY:
                return self._binop(ccall, "And", self._shr(ccall, dep_1, ARMG_CC_SHIFT_N), one)
            return None

        if flag == "z":
            if op == ARMG_CC_OP_SUB:
                return self._cmp(ccall, "CmpEQ", dep_1, dep_2)
            if op == ARMG_CC_OP_ADD:
                return self._cmp(ccall, "CmpEQ", self._binop(ccall, "Add", dep_1, dep_2), zero)
            if op in {ARMG_CC_OP_ADC, ARMG_CC_OP_SBB}:
                return self._cmp(ccall, "CmpEQ", self._carry_result(ccall, op, dep_1, dep_2, dep_3), zero)
            if op in {ARMG_CC_OP_LOGIC, ARMG_CC_OP_MUL}:
                return self._cmp(ccall, "CmpEQ", dep_1, zero)
            if op == ARMG_CC_OP_MULL:
                return self._cmp(ccall, "CmpEQ", self._binop(ccall, "Or", dep_1, dep_2), zero)
            if op == ARMG_CC_OP_COPY:
                return self._binop(ccall, "And", self._shr(ccall, dep_1, ARMG_CC_SHIFT_Z), one)
            return None

        if flag == "v":
            if op == ARMG_CC_OP_SUB:
                res = self._binop(ccall, "Sub", dep_1, dep_2)
                v = self._binop(
                    ccall, "And", self._binop(ccall, "Xor", dep_1, dep_2), self._binop(ccall, "Xor", dep_1, res)
                )
                return self._shr(ccall, v, 31)
            if op == ARMG_CC_OP_ADD:
                res = self._binop(ccall, "Add", dep_1, dep_2)
                v = self._binop(
                    ccall, "And", self._binop(ccall, "Xor", res, dep_1), self._binop(ccall, "Xor", res, dep_2)
                )
                return self._shr(ccall, v, 31)
            if op == ARMG_CC_OP_LOGIC:
                return dep_3
            if op in {ARMG_CC_OP_MUL, ARMG_CC_OP_MULL}:
                return self._binop(ccall, "And", dep_3, one)
            if op == ARMG_CC_OP_COPY:
                return self._binop(ccall, "And", self._shr(ccall, dep_1, ARMG_CC_SHIFT_V), one)
            return None

        return None

    # ---- helpers ----

    @staticmethod
    def _normalize_op(op: int, dep_3: Expr.Expression) -> int:
        if op == ARMG_CC_OP_ADC and ARMCCallRewriter._is_const(dep_3, 0):
            return ARMG_CC_OP_ADD
        if op == ARMG_CC_OP_SBB and ARMCCallRewriter._is_const(dep_3, 1):
            return ARMG_CC_OP_SUB
        return op

    def _carry_result(
        self,
        ccall: Expr.VEXCCallExpression,
        op: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        dep_3: Expr.Expression,
    ) -> Expr.BinaryOp:
        if op == ARMG_CC_OP_ADC:
            return self._binop(ccall, "Add", self._binop(ccall, "Add", dep_1, dep_2), dep_3)
        # SBB: dep_1 - dep_2 - (dep_3 ^ 1)
        borrow = self._binop(ccall, "Xor", dep_3, self._const(ccall, 1))
        return self._binop(ccall, "Sub", self._binop(ccall, "Sub", dep_1, dep_2), borrow)

    @staticmethod
    def _is_const(expr: Expr.Expression, value: int) -> bool:
        return isinstance(expr, Expr.Const) and expr.value_int == value

    def _const(self, ccall: Expr.VEXCCallExpression, value: int, bits: int = 32) -> Expr.Const:
        return Expr.Const(self.ail_manager.next_atom(), value, bits, **ccall.tags)

    def _binop(self, ccall: Expr.VEXCCallExpression, op: str, a: Expr.Expression, b: Expr.Expression) -> Expr.BinaryOp:
        return Expr.BinaryOp(self.ail_manager.next_atom(), op, (a, b), False, **ccall.tags)

    def _shr(self, ccall: Expr.VEXCCallExpression, a: Expr.Expression, amount: int) -> Expr.BinaryOp:
        return self._binop(ccall, "Shr", a, self._const(ccall, amount, 8))

    def _cmp(
        self, ccall: Expr.VEXCCallExpression, op: str, a: Expr.Expression, b: Expr.Expression, signed: bool = False
    ) -> Expr.BinaryOp:
        return Expr.BinaryOp(self.ail_manager.next_atom(), op, (a, b), signed, bits=1, **ccall.tags)

    def _is_nonzero(self, ccall: Expr.VEXCCallExpression, a: Expr.Expression, nonzero: bool) -> Expr.BinaryOp:
        return self._cmp(ccall, "CmpNE" if nonzero else "CmpEQ", a, self._const(ccall, 0, a.bits))

    def _logical(
        self, ccall: Expr.VEXCCallExpression, op: str, a: Expr.Expression, b: Expr.Expression
    ) -> Expr.BinaryOp:
        return Expr.BinaryOp(self.ail_manager.next_atom(), op, (a, b), False, bits=1, **ccall.tags)

    def _wrap(self, ccall: Expr.VEXCCallExpression, r: Expr.Expression) -> Expr.Expression:
        if r.bits == ccall.bits:
            return r
        return Expr.Convert(ccall.idx, r.bits, ccall.bits, False, r, **ccall.tags)
