import operator

from archinfo.arch_soot import SootNullConstant
import claripy

from ..values import SimSootValue_StringRef, SimSootValue_ThisRef
from .base import SimSootExpr


class SimSootExpr_Condition(SimSootExpr):
    def _execute(self):
        v1 = self._translate_expr(self.expr.value1)
        v2 = self._translate_expr(self.expr.value2)
        operator_func = SimSootExpr_Condition.condition_str_to_function[self.expr.op]
        if isinstance(v1.expr, SimSootValue_ThisRef) and isinstance(v2.expr, SootNullConstant) and v1.expr.symbolic:
            # TODO fix this
            self.expr = operator_func(claripy.BVS("obf_ref", 32), claripy.BVV(0, 32))
        elif isinstance(v1.expr, (SootNullConstant, SimSootValue_StringRef)) or isinstance(
            v2.expr, (SootNullConstant, SimSootValue_StringRef)
        ):
            self.expr = claripy.true if operator_func(v1.expr, v2.expr) else claripy.false
        else:
            self.expr = operator_func(v1.expr, v2.expr)

    # Java only has signed primitives
    condition_str_to_function = {
        "eq": operator.eq,
        "ne": operator.ne,
        "ge": claripy.SGE,
        "gt": claripy.SGT,
        "le": claripy.SLE,
        "lt": claripy.SLT
        # TODO others...
    }
