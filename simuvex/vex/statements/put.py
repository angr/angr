from . import SimIRStmt
from ... import s_options as o
from ...s_action_object import SimActionObject
from ...s_action import SimActionData
from ...s_variable import SimRegisterVariable

class SimIRStmt_Put(SimIRStmt):
    def _execute(self):
        # value to put
        data = self._translate_expr(self.stmt.data)

        if o.FRESHNESS_ANALYSIS in self.state.options:
            var = SimRegisterVariable(self.stmt.offset, data.expr.size() / 8)
            self.state.used_variables.add(var)

        # do the put (if we should)
        if o.DO_PUTS in self.state.options:
            self.state.store_reg(self.stmt.offset, data.expr)

        # track the put
        if o.REGISTER_REFS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            r = SimActionData(self.state, SimActionData.REG, SimActionData.WRITE, offset=self.stmt.offset, data=data_ao, size=size_ao)
            self.actions.append(r)

