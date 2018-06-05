
from .base import SimSootExpr
from ..values import SimSootValue_ThisRef
from ..values import SimSootValue_InstanceFieldRef


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
        # We need to strip away the quotes introduced by soot in case of a string constant
        heap_allocation_id = self.state.memory.get_new_uuid()
        this_ref = SimSootValue_ThisRef(heap_allocation_id, self.expr.type)
        field_ref = SimSootValue_InstanceFieldRef(heap_allocation_id, self.expr.type, 'value', self.expr.type)
        value = self.state.se.StringV(self.expr.value.strip("\""))
        self.state.memory.store(field_ref, value)
        self.expr = this_ref

