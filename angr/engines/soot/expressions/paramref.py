
from .base import SimSootExpr

class SimSootExpr_ParamRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ParamRef, self).__init__(expr, state)

    def _execute(self):
        # Parse the expr to get a SimSootValue_ParamRef instance
        ref = self._translate_value(self.expr)
        self.expr = ref


class SimSootExpr_ArrayRef(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_ArrayRef, self).__init__(expr, state)

    def _execute(self):
        # Parse the expr to get a SimSootValue_ParamRef instance
        ref = self._translate_value(self.expr)
        self.expr = ref
        # HACK: JUST TO TRY!!!
        self.expr = self.state.se.StringS("prova", 7)