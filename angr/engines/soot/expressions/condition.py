
import operator
from .base import SimSootExpr


class SimSootExpr_Condition(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Condition, self).__init__(expr, state)

    def _execute(self):
        v1 = self._translate_expr(self.expr.value1)
        v2 = self._translate_expr(self.expr.value2)

        new_expr = SimSootExpr_Condition.condition_str_to_function[self.expr.op](v1.expr, v2.expr)
        self.expr = new_expr

    condition_str_to_function = {
        "eq": operator.eq,
        "ne": operator.ne,
        "ge": operator.ge,
        "gt": operator.gt,
        "le": operator.le,
        "lt": operator.lt
        # TODO others...
    }

