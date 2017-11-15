from . import SimIRStmt
from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData

class SimIRStmt_PutI(SimIRStmt):
    def _execute(self):
        #pylint:disable=attribute-defined-outside-init

        # value to put
        data = self._translate_expr(self.stmt.data)
        expr = data.expr.raw_to_bv()

        # reg array data
        self.ix = self._translate_expr(self.stmt.ix)
        self.array_size = self.size_bytes(self.stmt.descr.elemTy)
        self.array_base = self.stmt.descr.base
        self.array_index = (self.ix.expr + self.stmt.bias) % self.stmt.descr.nElems
        self.offset = self.array_base + self.array_index*self.array_size

        # track the put
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            data_ao = SimActionObject(expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            a = SimActionData(self.state, SimActionData.REG, SimActionData.WRITE, addr=self.offset, data=data_ao, size=size_ao)
            self.actions.append(a)
        else:
            a = None

        # do the put (if we should)
        if o.DO_PUTS in self.state.options:
            self.state.registers.store(self.offset, expr, action=a)
