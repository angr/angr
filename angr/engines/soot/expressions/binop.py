from __future__ import annotations
import operator

from .base import SimSootExpr


class SimSootExpr_Binop(SimSootExpr):
    def _execute(self):
        v1 = self._translate_expr(self.expr.value1)
        v2 = self._translate_expr(self.expr.value2)
        operator_func = SimSootExpr_Binop.binop_str_to_function[self.expr.op]
        self.expr = operator_func(v1.expr, v2.expr)

    binop_str_to_function = {
        "add": operator.add,
        "sub": operator.sub,
        "and": operator.and_,
        "div": operator.truediv,
        "mul": operator.mul,
        "or": operator.or_,
        "shl": operator.lshift,
        "shr": operator.rshift,
        # "ushr": operator.rshift, #TODO
        "xor": operator.xor,
        "rem": operator.imod,
        "cmpl": operator.lt,
        "cmp": operator.ne,
    }
