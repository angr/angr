
import operator
from .base import SimSootExpr


class SimSootExpr_Binop(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Binop, self).__init__(expr, state)

    def _execute(self):
        v1 = self._translate_expr(self.expr.value1)
        v2 = self._translate_expr(self.expr.value2)

        new_expr = SimSootExpr_Binop.binop_str_to_function[self.expr.op](v1.expr, v2.expr)
        self.expr = new_expr

    binop_str_to_function = {
        "add": operator.add,
        "sub": operator.sub,
        "and": operator.and_,
        "div": operator.div,
        "mul": operator.mul,
        "or": operator.or_,
        "shl": operator.lshift,
        "shr": operator.rshift,
        # "ushr": operator.rshift, #TODO
        "xor": operator.xor,
        "rem": operator.imod
    }

