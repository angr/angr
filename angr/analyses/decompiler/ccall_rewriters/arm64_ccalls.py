from __future__ import annotations

from angr.ailment import Expr
from angr.engines.vex.claripy.ccall import (
    ARM64G_CC_OP_ADC32,
    ARM64G_CC_OP_ADC64,
    ARM64G_CC_OP_ADD32,
    ARM64G_CC_OP_ADD64,
    ARM64G_CC_OP_COPY,
    ARM64G_CC_OP_LOGIC32,
    ARM64G_CC_OP_LOGIC64,
    ARM64G_CC_OP_SBC32,
    ARM64G_CC_OP_SBC64,
    ARM64G_CC_OP_SUB32,
    ARM64G_CC_OP_SUB64,
    ARMG_CC_OP_ADC,
    ARMG_CC_OP_ADD,
    ARMG_CC_OP_COPY,
    ARMG_CC_OP_LOGIC,
    ARMG_CC_OP_SBB,
    ARMG_CC_OP_SUB,
    ARM64CondAL,
    ARM64CondCC,
    ARM64CondEQ,
    ARM64CondGE,
    ARM64CondGT,
    ARM64CondLE,
    ARM64CondLS,
    ARM64CondLT,
    ARM64CondMI,
    ARM64CondNE,
    ARM64CondNV,
    ARM64CondPL,
    ARM64CondVC,
)

from .arm_ccalls import ARMCCallRewriter

# AArch64 cc_op -> (the ARM cc_op that computes the same flags, operation width)
_OPS: dict[int, tuple[int, int]] = {
    ARM64G_CC_OP_COPY: (ARMG_CC_OP_COPY, 64),
    ARM64G_CC_OP_ADD32: (ARMG_CC_OP_ADD, 32),
    ARM64G_CC_OP_ADD64: (ARMG_CC_OP_ADD, 64),
    ARM64G_CC_OP_SUB32: (ARMG_CC_OP_SUB, 32),
    ARM64G_CC_OP_SUB64: (ARMG_CC_OP_SUB, 64),
    ARM64G_CC_OP_ADC32: (ARMG_CC_OP_ADC, 32),
    ARM64G_CC_OP_ADC64: (ARMG_CC_OP_ADC, 64),
    ARM64G_CC_OP_SBC32: (ARMG_CC_OP_SBB, 32),
    ARM64G_CC_OP_SBC64: (ARMG_CC_OP_SBB, 64),
    ARM64G_CC_OP_LOGIC32: (ARMG_CC_OP_LOGIC, 32),
    ARM64G_CC_OP_LOGIC64: (ARMG_CC_OP_LOGIC, 64),
}


class ARM64CCallRewriter(ARMCCallRewriter):
    """
    Rewrites ``arm64g_calculate_condition`` following libVEX's guest_arm64_helpers.c. AArch64 evaluates condition codes
    like AArch32 except that NV always holds and logical operations clear C and V, so each AArch64 cc_op is rewritten
    as the ARM cc_op that computes the same flags, at the operation's width. 32-bit operations use the low halves of
    their 64-bit operands.
    """

    __slots__ = ()

    def _rewrite(self, ccall: Expr.VEXCCallExpression) -> Expr.Expression | None:
        if len(ccall.operands) != 4 or self._original_callee(ccall) != "arm64g_calculate_condition":
            return None
        cond_n_op = ccall.operands[0]
        if not isinstance(cond_n_op, Expr.Const):
            return None
        cond = (cond_n_op.value_int >> 4) & 0xF
        op = cond_n_op.value_int & 0xF
        if cond in {ARM64CondAL, ARM64CondNV}:
            return Expr.Const(ccall.idx, 1, ccall.bits, **ccall.tags)
        if op not in _OPS:
            return None
        arm_op, bits = _OPS[op]
        deps = [self._to_bits(dep, bits, ccall.tags) for dep in ccall.operands[1:]]
        r = self._condition(ccall, cond, arm_op, *deps)
        return None if r is None else self._wrap(ccall, r)

    def _cond_logic(
        self, ccall: Expr.VEXCCallExpression, cond: int, op: int, res: Expr.Expression, shco: Expr.Expression
    ) -> Expr.Expression | None:
        # C and V are clear, so N == V is res >= 0
        zero = self._const(ccall, 0, res.bits)
        if cond in {ARM64CondEQ, ARM64CondNE}:
            return self._cmp(ccall, "CmpEQ" if cond == ARM64CondEQ else "CmpNE", res, zero)
        if cond in {ARM64CondMI, ARM64CondLT}:
            return self._cmp(ccall, "CmpLT", res, zero, True)
        if cond in {ARM64CondPL, ARM64CondGE}:
            return self._cmp(ccall, "CmpGE", res, zero, True)
        if cond == ARM64CondGT:
            return self._cmp(ccall, "CmpGT", res, zero, True)
        if cond == ARM64CondLE:
            return self._cmp(ccall, "CmpLE", res, zero, True)
        # CS, VS and HI never hold; CC, VC and LS always do
        holds = cond in {ARM64CondCC, ARM64CondVC, ARM64CondLS}
        return Expr.Const(self.ail_manager.next_atom(), int(holds), ccall.bits, **ccall.tags)
