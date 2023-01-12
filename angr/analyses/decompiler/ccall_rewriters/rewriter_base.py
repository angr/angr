from typing import Optional

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
        self.result: Optional[ailment.Expr.Expression] = self._rewrite(ccall)

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> Optional[ailment.Expr.Expression]:
        raise NotImplementedError()
