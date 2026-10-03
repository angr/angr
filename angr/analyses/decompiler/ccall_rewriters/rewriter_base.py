from __future__ import annotations

from typing import TYPE_CHECKING

from angr import ailment
from angr.sim_type import SimTypeDouble, SimTypeFunction, SimTypeInt

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

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError
