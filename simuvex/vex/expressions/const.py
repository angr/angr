from .base import SimIRExpr
from ...s_helpers import translate_irconst

class SimIRExpr_Const(SimIRExpr):
	def _execute(self):
		self.expr = translate_irconst(self.state, self._expr.con)

