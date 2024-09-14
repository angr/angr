from __future__ import annotations
from . import translate_expr
from ..values import translate_value


class SimSootExpr:
    def __init__(self, expr, state):
        self.expr = expr
        self.state = state

    def process(self):
        self._execute()

    def _execute(self):
        raise NotImplementedError

    def _translate_expr(self, expr):
        return translate_expr(expr, self.state)

    def _translate_value(self, value):
        return translate_value(value, self.state)
