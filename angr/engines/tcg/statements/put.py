from . import SimIRStmt
from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData

class SimIRStmt_Put(SimIRStmt):
    def _execute(self):
        # value to put
        data = self._translate_expr(self.stmt.data)

        # track the put
        if o.TRACK_REGISTER_ACTIONS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            a = SimActionData(self.state, SimActionData.REG, SimActionData.WRITE, addr=self.stmt.offset, data=data_ao, size=size_ao)
            self.actions.append(a)
        else:
            a = None

        # do the put (if we should)
        if o.DO_PUTS in self.state.options:
            self.state.registers.store(self.stmt.offset, data.expr, action=a)
