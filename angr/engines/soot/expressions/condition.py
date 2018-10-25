
import operator

from archinfo.arch_soot import SootNullConstant
import claripy

from ..values.strref import SimSootValue_StringRef
from .base import SimSootExpr


class SimSootExpr_Condition(SimSootExpr):
    def _execute(self):
        v1 = self._translate_expr(self.expr.value1)
        v2 = self._translate_expr(self.expr.value2)
        operator_func = SimSootExpr_Condition.condition_str_to_function[self.expr.op]
        if isinstance(v1.expr, (SootNullConstant, SimSootValue_StringRef)) or \
           isinstance(v2.expr, (SootNullConstant, SimSootValue_StringRef)):
            self.expr = claripy.true if operator_func(v1.expr, v2.expr) else claripy.false
        else:
            self.expr = operator_func(v1.expr, v2.expr)

    condition_str_to_function = {
        "eq": operator.eq,
        "ne": operator.ne,
        "ge": operator.ge,
        "gt": operator.gt,
        "le": operator.le,
        "lt": operator.lt
        # TODO others...
    }
