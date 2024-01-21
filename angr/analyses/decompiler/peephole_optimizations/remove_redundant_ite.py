from ailment.expression import ITE

from .base import PeepholeOptimizationExprBase


class RedundantITE(PeepholeOptimizationExprBase):
    __slots__ = ()

    NAME = "expr?a:b"
    expr_classes = (ITE,)

    def optimize(self, expr: ITE, **kwargs):
        if expr.iffalse.likes(expr.iftrue):
            import ipdb;ipdb.set_trace()
        return None
