from .base import SimIRExpr
from ... import s_options as o
from ...s_action import SimActionData

class SimIRExpr_RdTmp(SimIRExpr):
    def _execute(self):
        if (o.SUPER_FASTPATH in self.state.options
                and self._expr.tmp not in self.state.scratch.temps):
            self.expr = self.state.BVV(0, self.size_bits())
        else:
            self.expr = self.state.scratch.tmp_expr(self._expr.tmp)

        # finish it and save the tmp reference
        self._post_process()
        if o.TRACK_TMP_ACTIONS in self.state.options:
            r = SimActionData(self.state, SimActionData.TMP, SimActionData.READ, tmp=self._expr.tmp, size=self.size_bits(), data=self.expr)
            self.actions.append(r)
