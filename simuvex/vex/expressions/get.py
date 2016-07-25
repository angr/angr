from .base import SimIRExpr
from .. import size_bytes
from ... import s_options as o
from ...s_action import SimActionData
from ...s_variable import SimRegisterVariable

class SimIRExpr_Get(SimIRExpr):
    def _execute(self):
        size = size_bytes(self._expr.type)
        self.type = self._expr.type

        if o.FRESHNESS_ANALYSIS in self.state.options:
            var = SimRegisterVariable(self._expr.offset, size)
            if not self.state.scratch.used_variables.contains_register_variable(var):
                self.state.scratch.input_variables.add_register_variable(var)

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
