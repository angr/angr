
from .base import SimSootExpr
from ..values import SimSootValue_ArrayRef


class SimSootExpr_NewArray(SimSootExpr):
    """
    Allocate a new array in memory and return the reference to that array
    """
    def __init__(self, expr, state):
        super(SimSootExpr_NewArray, self).__init__(expr, state)

    def _execute(self):
        # TODO: Handle different types of array
        type_ = self.expr.type.strip("[]")
        # Size can be symbolic
        array_size = self._translate_expr(self.expr.size).expr
        if self.state.se.symbolic(array_size):
            size = self.state.memory.max_array_size
        else:
            size = self.state.se.eval(array_size)

        self.expr = [self.state.se.BVV(0, 32)]*size

