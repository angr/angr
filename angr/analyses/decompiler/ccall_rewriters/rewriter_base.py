from __future__ import annotations
import angr.ailment as ailment


class CCallRewriterBase:
    """
    The base class for CCall rewriters.
    """

    __slots__ = (
        "arch",
        "result",
    )

    def __init__(self, ccall: ailment.Expr.VEXCCallExpression, arch, rename_ccalls: bool = False):
        self.arch = arch
        self.result: ailment.Expr.Expression | None = self._rewrite(ccall)
        if rename_ccalls and self.result is None and ccall.callee != "_ccall":
            renamed = ccall.copy()
            renamed.callee = "_ccall"
            self.result = renamed

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> ailment.Expr.Expression | None:
        raise NotImplementedError
