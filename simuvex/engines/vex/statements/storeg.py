from . import SimIRStmt
from ... import s_options as o
from ...s_action_object import SimActionObject
from ...s_action import SimActionData

class SimIRStmt_StoreG(SimIRStmt):
    def _execute(self):
        addr = self._translate_expr(self.stmt.addr)
        data = self._translate_expr(self.stmt.data)
        expr = data.expr.to_bv()
        guard = self._translate_expr(self.stmt.guard)

        if o.TRACK_MEMORY_ACTIONS in self.state.options:
            data_ao = SimActionObject(expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(guard.expr, reg_deps=guard.reg_deps(), tmp_deps=guard.tmp_deps())
            size_ao = SimActionObject(data.size_bits())

            a = SimActionData(self.state, self.state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
            self.actions.append(a)
        else:
            a = None

        self.state.memory.store(addr.expr, expr, condition=guard.expr == 1, endness=self.stmt.end, action=a)
