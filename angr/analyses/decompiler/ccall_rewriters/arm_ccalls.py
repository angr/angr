from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import (
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
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_MUL,
    ARMG_CC_OP_NUMBER,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
)

from .rewriter_base import CCallRewriterBase

# Valid ARM CC operation range
_VALID_CC_OPS = range(ARMG_CC_OP_NUMBER)


class ARMCCallRewriter(CCallRewriterBase):
    """
    ARM condition codes encode flag checks on N, Z, C, V flags. The ``cond_n_op``
    operand packs condition (upper 4 bits) and cc_op (lower 4 bits). Conditions
    come in pairs where the odd member inverts the even one (inv = cond & 1).

    Flag semantics per operation:

    SUB (CMP):  N = sign(dep1-dep2), Z = (dep1==dep2), C = (dep1 >=u dep2), V = signed overflow
    ADD (CMN):  N = sign(dep1+dep2), Z = (dep1+dep2==0), C = unsigned carry, V = signed overflow
    LOGIC:      N = sign(dep1), Z = (dep1==0), C = dep2 (shifter carry), V = dep3 (old V)
    MUL:        N = sign(dep1), Z = (dep1==0), C/V from dep3
    SBB:        like SUB but with borrow: dep1 - dep2 - (dep3^1)

    Also handles individual flag helpers (armg_calculate_flag_c/n/z/v) and
    previously-renamed ``_ccall`` expressions (common when constant propagation
    resolves operands after the initial rename pass).
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if ccall.callee == "armg_calculate_condition":
            return self._rewrite_condition(ccall)
        if ccall.callee == "armg_calculate_flag_c":
            return self._rewrite_flag_c(ccall)
        if ccall.callee == "armg_calculate_flag_n":
            return self._rewrite_flag_n(ccall)
        if ccall.callee == "armg_calculate_flag_z":
            return self._rewrite_flag_z(ccall)
        # _ccall: try to interpret as armg_calculate_condition (the callee name
        # was lost during a prior rename pass when the operands were still
        # non-constant; constant propagation may have resolved them since)
        if ccall.callee == "_ccall" and len(ccall.operands) == 4:
            return self._rewrite_renamed_ccall(ccall)
        return None

    # ---- armg_calculate_condition ----

    def _rewrite_condition(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        cond_n_op = ccall.operands[0]
        if not isinstance(cond_n_op, Expr.Const):
            return None
        return self._do_rewrite_condition(ccall, cond_n_op.value_int)

    def _rewrite_renamed_ccall(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        """Try to rewrite a ``_ccall`` as ``armg_calculate_condition``."""
        cond_n_op = ccall.operands[0]
        if not isinstance(cond_n_op, Expr.Const):
            return None
        val = cond_n_op.value_int
        cond = val >> 4
        op = val & 0xF
        # Sanity: valid condition code (0-15) and valid cc_op
        if cond > 15 or op not in _VALID_CC_OPS:
            return None
        return self._do_rewrite_condition(ccall, val)

    def _do_rewrite_condition(self, ccall: Expr.VEXCCallExpression, concrete_cond_n_op: int) -> Expr.Expression | None:
        cond_v = concrete_cond_n_op >> 4
        op_v = concrete_cond_n_op & 0xF
        inv = cond_v & 1

        dep_1 = ccall.operands[1]
        dep_2 = ccall.operands[2]
        dep_3 = ccall.operands[3]

        # AL (always) / NV (never) — independent of operation
        if cond_v == ARMCondAL:
            return Expr.Const(ccall.idx, None, 1, ccall.bits, **ccall.tags)
        if cond_v == ARMCondNV:
            return Expr.Const(ccall.idx, None, 0, ccall.bits, **ccall.tags)

        if op_v == ARMG_CC_OP_SUB:
            return self._rewrite_sub(ccall, cond_v, inv, dep_1, dep_2)
        if op_v == ARMG_CC_OP_ADD:
            return self._rewrite_add(ccall, cond_v, inv, dep_1, dep_2)
        if op_v == ARMG_CC_OP_LOGIC:
            return self._rewrite_logic(ccall, cond_v, inv, dep_1)
        if op_v == ARMG_CC_OP_MUL:
            return self._rewrite_logic(ccall, cond_v, inv, dep_1)
        if op_v == ARMG_CC_OP_SBB:
            return self._rewrite_sbb(ccall, cond_v, inv, dep_1, dep_2, dep_3)

        return None

    # ---- individual flag helpers ----

    def _rewrite_flag_c(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        """armg_calculate_flag_c(cc_op, dep1, dep2, dep3) → C flag."""
        cc_op = ccall.operands[0]
        if not isinstance(cc_op, Expr.Const):
            return None
        op_v = cc_op.value_int
        dep_1 = ccall.operands[1]
        dep_2 = ccall.operands[2]
        dep_3 = ccall.operands[3]

        if op_v == ARMG_CC_OP_SUB:
            # C = (dep_1 >=u dep_2)
            r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v == ARMG_CC_OP_ADD:
            # C = unsigned carry: (dep_1 + dep_2) <u dep_1
            add_expr = Expr.BinaryOp(None, "Add", (dep_1, dep_2), signed=False, **ccall.tags)
            r = Expr.BinaryOp(ccall.idx, "CmpLT", (add_expr, dep_1), signed=False, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v == ARMG_CC_OP_SBB:
            # C = if dep_3==0 then dep_1>=dep_2 else dep_1>dep_2
            if isinstance(dep_3, Expr.Const) and dep_3.value_int == 0:
                r = Expr.BinaryOp(ccall.idx, "CmpGE", (dep_1, dep_2), signed=False, **ccall.tags)
            else:
                r = Expr.BinaryOp(ccall.idx, "CmpGT", (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v == ARMG_CC_OP_LOGIC:
            # C = dep_2 (shifter carry out)
            return dep_2

        return None

    def _rewrite_flag_n(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        """armg_calculate_flag_n(cc_op, dep1, dep2, dep3) → N flag (sign bit)."""
        cc_op = ccall.operands[0]
        if not isinstance(cc_op, Expr.Const):
            return None
        op_v = cc_op.value_int
        dep_1 = ccall.operands[1]
        dep_2 = ccall.operands[2]
        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

        if op_v == ARMG_CC_OP_SUB:
            # N = sign(dep_1 - dep_2) → (dep_1 - dep_2) <s 0 → dep_1 <s dep_2
            r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, dep_2), signed=True, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v == ARMG_CC_OP_ADD:
            # N = sign(dep_1 + dep_2) → (dep_1 + dep_2) <s 0
            add_expr = Expr.BinaryOp(None, "Add", (dep_1, dep_2), signed=False, **ccall.tags)
            r = Expr.BinaryOp(ccall.idx, "CmpLT", (add_expr, zero), signed=True, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v in {ARMG_CC_OP_LOGIC, ARMG_CC_OP_MUL}:
            # N = sign(dep_1) → dep_1 <s 0
            r = Expr.BinaryOp(ccall.idx, "CmpLT", (dep_1, zero), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        return None

    def _rewrite_flag_z(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        """armg_calculate_flag_z(cc_op, dep1, dep2, dep3) → Z flag (zero test)."""
        cc_op = ccall.operands[0]
        if not isinstance(cc_op, Expr.Const):
            return None
        op_v = cc_op.value_int
        dep_1 = ccall.operands[1]
        dep_2 = ccall.operands[2]
        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

        if op_v == ARMG_CC_OP_SUB:
            # Z = (dep_1 == dep_2)
            r = Expr.BinaryOp(ccall.idx, "CmpEQ", (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v == ARMG_CC_OP_ADD:
            # Z = (dep_1 + dep_2) == 0
            add_expr = Expr.BinaryOp(None, "Add", (dep_1, dep_2), signed=False, **ccall.tags)
            r = Expr.BinaryOp(ccall.idx, "CmpEQ", (add_expr, zero), signed=False, **ccall.tags)
            return self._wrap(ccall, r)
        if op_v in {ARMG_CC_OP_LOGIC, ARMG_CC_OP_MUL}:
            # Z = (dep_1 == 0)
            r = Expr.BinaryOp(ccall.idx, "CmpEQ", (dep_1, zero), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        return None

    # ---- helpers ----

    @staticmethod
    def _wrap(ccall: Expr.VEXCCallExpression, r: Expr.BinaryOp) -> Expr.Expression:
        """Wrap a 1-bit comparison result to match the ccall's output width."""
        if r.bits == ccall.bits:
            return r
        return Expr.Convert(None, r.bits, ccall.bits, False, r, **ccall.tags)

    # ---- SUB (CMP instruction) ----

    def _rewrite_sub(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        SUB: flags from ``dep_1 - dep_2`` (CMP instruction).

        Z = (dep_1 == dep_2)
        C = (dep_1 >=u dep_2)   [no borrow]
        N = sign(dep_1 - dep_2)
        V = signed overflow of dep_1 - dep_2

        For SUB, the compound signed conditions (GE/LT checking N==V, GT/LE
        checking !Z && N==V) are exactly equivalent to signed comparisons.
        """

        # EQ/NE — Z flag (exact)
        if cond_v in {ARMCondEQ, ARMCondNE}:
            op = "CmpEQ" if inv == 0 else "CmpNE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        # HS/LO — C flag, unsigned (exact)
        if cond_v in {ARMCondHS, ARMCondLO}:
            op = "CmpGE" if inv == 0 else "CmpLT"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        # MI/PL — N flag, sign of difference (approximate: ignores overflow)
        if cond_v in {ARMCondMI, ARMCondPL}:
            op = "CmpLT" if inv == 0 else "CmpGE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        # HI/LS — C=1 && Z=0, unsigned greater / unsigned less-or-same (exact)
        if cond_v in {ARMCondHI, ARMCondLS}:
            op = "CmpGT" if inv == 0 else "CmpLE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        # GE/LT — N==V, signed greater-or-equal / signed less (exact for SUB)
        if cond_v in {ARMCondGE, ARMCondLT}:
            op = "CmpGE" if inv == 0 else "CmpLT"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        # GT/LE — !Z && N==V, signed greater / signed less-or-equal (exact for SUB)
        if cond_v in {ARMCondGT, ARMCondLE}:
            op = "CmpGT" if inv == 0 else "CmpLE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        # VS/VC — overflow: not expressible as simple comparison
        return None

    # ---- ADD (CMN instruction, or flags from addition) ----

    def _rewrite_add(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        ADD: flags from ``dep_1 + dep_2``.
        """
        add_expr = Expr.BinaryOp(None, "Add", (dep_1, dep_2), signed=False, **ccall.tags)
        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

        # EQ/NE — Z flag: (dep_1 + dep_2) == 0
        if cond_v in {ARMCondEQ, ARMCondNE}:
            op = "CmpEQ" if inv == 0 else "CmpNE"
            r = Expr.BinaryOp(ccall.idx, op, (add_expr, zero), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        # MI/PL — N flag: sign(dep_1 + dep_2) → (dep_1 + dep_2) <s 0
        if cond_v in {ARMCondMI, ARMCondPL}:
            op = "CmpLT" if inv == 0 else "CmpGE"
            r = Expr.BinaryOp(ccall.idx, op, (add_expr, zero), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        return None

    # ---- LOGIC / MUL (result in dep_1) ----

    def _rewrite_logic(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        inv: int,
        dep_1: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        LOGIC: flags from AND/OR/XOR result (dep_1 = result).
        MUL:   flags from multiply result (dep_1 = result).
        """
        zero = Expr.Const(None, None, 0, dep_1.bits, **ccall.tags)

        # EQ/NE — Z flag: dep_1 == 0
        if cond_v in {ARMCondEQ, ARMCondNE}:
            op = "CmpEQ" if inv == 0 else "CmpNE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, zero), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        # MI/PL — N flag: dep_1 < 0 (signed)
        if cond_v in {ARMCondMI, ARMCondPL}:
            op = "CmpLT" if inv == 0 else "CmpGE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, zero), signed=True, **ccall.tags)
            return self._wrap(ccall, r)

        return None

    # ---- SBB (subtract with borrow) ----

    def _rewrite_sbb(
        self,
        ccall: Expr.VEXCCallExpression,
        cond_v: int,
        inv: int,
        dep_1: Expr.Expression,
        dep_2: Expr.Expression,
        dep_3: Expr.Expression,
    ) -> Expr.Expression | None:
        """
        SBB: flags from ``dep_1 - dep_2 - (dep_3 ^ 1)``.
        C flag: if dep_3==0 then dep_1 >= dep_2 else dep_1 > dep_2.
        """
        # HS/LO — C flag (unsigned)
        if cond_v in {ARMCondHS, ARMCondLO}:
            if isinstance(dep_3, Expr.Const) and dep_3.value_int == 0:
                op = "CmpGE" if inv == 0 else "CmpLT"
            else:
                op = "CmpGT" if inv == 0 else "CmpLE"
            r = Expr.BinaryOp(ccall.idx, op, (dep_1, dep_2), signed=False, **ccall.tags)
            return self._wrap(ccall, r)

        return None
