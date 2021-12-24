from typing import Optional

import ailment


class CCallRewriterBase:
    """
    The base class for CCall rewriters.
    """

    __slots__ = ('result', )

    def __init__(self, ccall: ailment.Expr.VEXCCallExpression):
        self.result: Optional[ailment.Expr.Expression] = self._rewrite(ccall)

    def _rewrite(self, ccall: ailment.Expr.VEXCCallExpression) -> Optional[ailment.Expr.Expression]:
        raise NotImplementedError()
