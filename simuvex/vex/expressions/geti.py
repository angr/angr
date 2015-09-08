from .base import SimIRExpr
from .. import size_bytes
from ... import s_options as o
from ...s_action import SimActionData
from ...s_variable import SimRegisterVariable

class SimIRExpr_GetI(SimIRExpr):
    def _execute(self):
        self.ix = self._translate_expr(self._expr.ix)
        size = size_bytes(self._expr.descr.elemTy)
        self.type = self._expr.descr.elemTy
        self.array_base = self._expr.descr.base
        self.array_index = (self.ix.expr + self._expr.bias) % self._expr.descr.nElems
        self.offset = self.array_base + self.array_index*size

        # FIXME: @fish will this code work with symbolic offset?
        if o.FRESHNESS_ANALYSIS in self.state.options:
            var = SimRegisterVariable(self.offset, size)
            if var not in self.state.scratch.used_variables:
                self.state.scratch.input_variables.add(var)

        # get it!
        self.expr = self.state.registers.load(self.offset, size)

        if self.type.startswith('Ity_F'):
            self.expr = self.expr.raw_to_fp()

        # finish it and save the register references
        self._post_process()
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            r = SimActionData(self.state, self.state.registers.id, SimActionData.READ, addr=self.offset, size=size, data=self.expr)
            self.actions.append(r)
