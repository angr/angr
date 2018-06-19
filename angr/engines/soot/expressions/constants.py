
from .base import SimSootExpr
from ..values import SimSootValue_InstanceFieldRef, SimSootValue_StringRef
from ..values.constants import SimSootValue_ClassConstant


class SimSootExpr_IntConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_IntConstant, self).__init__(expr, state)

    def _execute(self):
        self.expr = self.state.se.BVV(self.expr.value, 32)

class SimSootExpr_LongConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_LongConstant, self).__init__(expr, state)

    def _execute(self):
        self.expr = self.state.se.BVV(self.expr.value, 64)

class SimSootExpr_StringConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_StringConstant, self).__init__(expr, state)

    def _execute(self):
        # strip away quotes introduced by soot
        str_val = self.state.se.StringV(self.expr.value.strip("\""))
        str_ref = SimSootValue_StringRef(self.state.memory.get_new_uuid())
        self.state.memory.store(str_ref, str_val)
        self.expr = str_ref

class SimSootExpr_ClassConstant(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ClassConstant, self).__init__(expr, state)

    def _execute(self):        
        self.expr = SimSootValue_ClassConstant.from_sootvalue(self.state, self.expr)
