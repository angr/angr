import logging

from angr.engines.soot.values.util import translate_value

l = logging.getLogger(__name__)


def translate_expr(expr, state):
    expr_name = expr.__class__.__name__.split(".")[-1]
    if expr_name.startswith("Soot"):
        expr_name = expr_name[4:]
    if expr_name.endswith("Expr"):
        expr_name = expr_name[:-4]
    expr_cls_name = "SimSootExpr_" + expr_name

    g = globals()
    if expr_cls_name in g:
        expr_cls = g[expr_cls_name]
    else:
        l.warning("Unsupported Soot expression %s.", expr_cls_name)
        expr_cls = SimSootExpr_Unsupported

    expr = expr_cls(expr, state)
    expr.process()
    return expr


class SimSootExpr:
    def __init__(self, expr, state):
        self.expr = expr
        self.state = state

    def process(self):
        self._execute()

    def _execute(self):
        raise NotImplementedError()

    def _translate_expr(self, expr):
        expr_ = translate_expr(expr, self.state)
        return expr_

    def _translate_value(self, value):
        value_ = translate_value(value, self.state)
        return value_


class SimSootExpr_Unsupported(SimSootExpr):
    def _execute(self):
        pass
