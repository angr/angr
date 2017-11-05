from . import SimIRStmt
from .... import sim_options as o
from ....state_plugins.sim_action_object import SimActionObject
from ....state_plugins.sim_action import SimActionData

class SimIRStmt_Store(SimIRStmt):
    def _execute(self):
        # first resolve the address and record stuff
        addr = self._translate_expr(self.stmt.addr)

        # now get the value and track everything
        data = self._translate_expr(self.stmt.data)
        expr = data.expr.raw_to_bv()

        # track the write
        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            data_ao = SimActionObject(expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            a = SimActionData(self.state, SimActionData.MEM, SimActionData.WRITE, data=data_ao, size=size_ao, addr=addr_ao)
            self.actions.append(a)
        else:
            a = None


        # Now do the store (if we should)
        if o.DO_STORES in self.state.options:
            self.state.memory.store(addr.expr, data.expr, action=a, endness=self.stmt.endness)
