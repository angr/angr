from __future__ import annotations

from typing import TYPE_CHECKING

import angr.ailment as ailment

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
            renamed = ccall.copy()
            renamed.callee = "_ccall"
            self.result = renamed

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError
