from __future__ import annotations

from typing import TYPE_CHECKING

from angr import ailment

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

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError
