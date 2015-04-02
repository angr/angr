from . import SimIRStmt
from ... import s_options as o
from ...s_action_object import SimActionObject
from ...s_action import SimActionData

class SimIRStmt_Store(SimIRStmt):
    def _execute(self):
        # first resolve the address and record stuff
        addr = self._translate_expr(self.stmt.addr)

        # now get the value and track everything
        data = self._translate_expr(self.stmt.data)

        # fix endianness
        data_endianness = data.expr.reversed if self.stmt.endness == "Iend_LE" else data.expr

        if o.FRESHNESS_ANALYSIS in self.state.options:
            self.state.log.used_variables.add_memory_variables(self.state.memory.normalize_address(addr.expr), data.expr.size() / 8)

        # Now do the store (if we should)
        if o.DO_STORES in self.state.options:
            self.state.store_mem(addr.expr, data_endianness, endness="Iend_BE")

        # track the write
        if o.MEMORY_REFS in self.state.options:
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            size_ao = SimActionObject(data.size_bits())
            r = SimActionData(self.state, SimActionData.MEM, SimActionData.WRITE, data=data_ao, size=size_ao, addr=addr_ao)
            self.actions.append(r)

