from .base import SimIRExpr
from .. import size_bytes
from simuvex import s_options as o
from simuvex.s_action import SimActionData

class SimIRExpr_Get(SimIRExpr):
    def _execute(self):
        size = size_bytes(self._expr.type)
        self.type = self._expr.type

        # get it!
        self.expr = self.state.registers.load(self._expr.offset, size)

        if self.type.startswith('Ity_F'):
            self.expr = self.expr.raw_to_fp()

        # finish it and save the register references
        self._post_process()
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            r = SimActionData(self.state, self.state.registers.id, SimActionData.READ, addr=self._expr.offset,
                              size=size, data=self.expr
                              )
            self.actions.append(r)
