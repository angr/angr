from .base import SimIRExpr
from .. import translate_irconst

class SimIRExpr_Const(SimIRExpr):
    def _execute(self):
        self.expr = translate_irconst(self.state, self._expr.con)

