from .base import SimIRExpr
from .... import sim_options as o
from ....state_plugins.sim_action import SimActionData

class SimIRExpr_GetI(SimIRExpr):
    def _execute(self):
        self.ix = self._translate_expr(self._expr.ix)  # pylint:disable=attribute-defined-outside-init
        size = self.size_bytes(self._expr.descr.elemTy)
        size_in_bits = self.size_bits(self._expr.descr.elemTy)
        self.type = self._expr.descr.elemTy
        self.array_base = self._expr.descr.base  # pylint:disable=attribute-defined-outside-init
        self.array_index = (self.ix.expr + self._expr.bias) % self._expr.descr.nElems  # pylint:disable=attribute-defined-outside-init
        self.offset = self.array_base + self.array_index*size  # pylint:disable=attribute-defined-outside-init

        # get it!
        self.expr = self.state.registers.load(self.offset, size)

        if self.type.startswith('Ity_F'):
            self.expr = self.expr.raw_to_fp()

        # finish it and save the register references
        self._post_process()
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            r = SimActionData(self.state, self.state.registers.id, SimActionData.READ, addr=self.offset, size=size_in_bits, data=self.expr)
            self.actions.append(r)
