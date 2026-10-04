from __future__ import annotations

from typing import TYPE_CHECKING

from angr import ailment
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeInt, SimTypeShort

if TYPE_CHECKING:
    from angr.ailment.manager import Manager


class CCallRewriterBase:
    """
    The base class for CCall rewriters.
    """

    __slots__ = (
        "ail_manager",
        "project",
        "result",
    )

    def __init__(
        self, ccall: ailment.Expr.VEXCCallExpression, project, ail_manager: Manager, rename_ccalls: bool = False
    ):
        self.project = project
        self.ail_manager = ail_manager
        self.result: ailment.Expr.Expression | None = self._rewrite(ccall)
        assert self.result is None or self.result.bits == ccall.bits, (
            f"Rewritten ccall expression has {self.result.bits} bits, expecting {ccall.bits} bits"
        )
        if rename_ccalls and self.result is None and ccall.callee != "_ccall":
            # keep the original callee so the ccall can still be rewritten once its operands become constant
            self.result = ailment.Expr.VEXCCallExpression(
                ccall.idx, "_ccall", ccall.operands, ccall.bits, **{**ccall.tags, "vex_callee": ccall.callee}
            )

    @staticmethod
    def _original_callee(ccall: ailment.Expr.VEXCCallExpression) -> str:
        if ccall.callee == "_ccall":
            callee = ccall.tags.get("vex_callee")
            if isinstance(callee, str):
                return callee
        return ccall.callee

    def _rewrite_fxam(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        """
        ``calculate_FXAM(tag, dbl)`` -> ``__fxam(value)``: the x87 tag is dropped (registers are assumed valid) and the
        I64 operand is viewed as the double it carries.
        """
        if len(ccall.operands) != 2:
            return None
        value = ccall.operands[1]
        if isinstance(value, ailment.Expr.Reinterpret) and value.from_type == "F" and value.to_type == "I":
            value = value.operand
        else:
            value = ailment.Expr.Reinterpret(self.ail_manager.next_atom(), 64, "I", 64, "F", value, **ccall.tags)
        return ailment.Expr.Call(
            ccall.idx,
            "__fxam",
            calling_convention=None,
            prototype=SimTypeFunction([SimTypeDouble()], SimTypeInt(signed=False)).with_arch(self.project.arch),
            args=(value,),
            bits=ccall.bits,
            **ccall.tags,
        )

    def _rewrite_control_word_read(
        self, ccall: ailment.Expr.VEXCCallExpression, helper: str
    ) -> ailment.Expr.Expression | None:
        """
        ``create_mxcsr(sseround)`` (stmxcsr) -> ``_mm_getcsr()`` and ``create_fpucw(fpround)`` (fnstcw) ->
        ``__fnstcw()``: VEX rebuilds the register from the modelled rounding mode, so read the real one instead.
        """
        if helper == "create_mxcsr":
            name, ret_ty = "_mm_getcsr", SimTypeInt(signed=False)
        elif helper == "create_fpucw":
            name, ret_ty = "__fnstcw", SimTypeShort(signed=False)
        else:
            return None
        ret_bits = ret_ty.with_arch(self.project.arch).size
        assert ret_bits is not None and ret_bits <= ccall.bits
        call = ailment.Expr.Call(
            ccall.idx if ret_bits == ccall.bits else self.ail_manager.next_atom(),
            name,
            calling_convention=None,
            prototype=SimTypeFunction([], ret_ty).with_arch(self.project.arch),
            args=(),
            bits=ret_bits,
            **ccall.tags,
        )
        if ret_bits == ccall.bits:
            return call
        return ailment.Expr.Convert(ccall.idx, ret_bits, ccall.bits, False, call, **ccall.tags)

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError

    def _copied_flag_test(
        self, ccall: ailment.Expr.VEXCCallExpression, flags: ailment.Expr.Expression, mask: int, flag_set: bool
    ) -> ailment.Expr.Expression:
        """A condition on flags stored verbatim (G_CC_OP_COPY): (flags & mask) != 0, or == 0 when the flags of
        *mask* must be clear."""
        masked = ailment.Expr.BinaryOp(
            self.ail_manager.next_atom(),
            "And",
            [flags, ailment.Expr.Const(self.ail_manager.next_atom(), mask, flags.bits)],
            False,
            **ccall.tags,
        )
        zero = ailment.Expr.Const(self.ail_manager.next_atom(), 0, flags.bits)
        r = ailment.Expr.BinaryOp(ccall.idx, "CmpNE" if flag_set else "CmpEQ", (masked, zero), False, **ccall.tags)
        return ailment.Expr.Convert(self.ail_manager.next_atom(), r.bits, ccall.bits, False, r, **ccall.tags)
