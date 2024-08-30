from __future__ import annotations
import ailment


class CCallRewriterBase:
    """
    The base class for CCall rewriters.
    """

    __slots__ = (
        "result",
        "arch",
    )

    def __init__(self, ccall: ailment.Expr.VEXCCallExpression, arch):
        self.arch = arch
        self.result: ailment.Expr.Expression | None = self._rewrite(ccall)

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError
