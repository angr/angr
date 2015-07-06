from . import SimIRStmt

# TODO: tmp write SimActions
# TODO: mem read SimActions

class SimIRStmt_CAS(SimIRStmt):
    def _execute(self):
        # first, get the expression of the add
        addr = self._translate_expr(self.stmt.addr)

        # figure out if it's a single or double
        double_element = (self.stmt.oldHi != 0xFFFFFFFF) and (self.stmt.expdHi is not None)

        if double_element:
            # translate the expected values
            expd_lo = self._translate_expr(self.stmt.expdLo)
            expd_hi = self._translate_expr(self.stmt.expdHi)

            # read the old values
            old_cnt = self.state.memory.load(addr.expr, len(expd_lo.expr)*2/8, endness=self.stmt.endness)
            old_hi, old_lo = old_cnt.chop(bits=len(expd_lo))
            self.state.scratch.store_tmp(self.stmt.oldLo, old_lo)
            self.state.scratch.store_tmp(self.stmt.oldHi, old_hi)

            # the write data
            data_lo = self._translate_expr(self.stmt.dataLo)
            data_hi = self._translate_expr(self.stmt.dataHi)
            data = self.state.se.Concat(data_hi.expr, data_lo.expr)

            # the condition
            condition = self.state.se.And(old_lo == expd_lo.expr, old_hi == expd_hi.expr)

            # do it
            data_tmp_deps = data_lo.tmp_deps() | data_hi.tmp_deps()
            data_reg_deps = data_lo.reg_deps() | data_hi.reg_deps()
            cond_tmp_deps = expd_lo.tmp_deps() | expd_hi.tmp_deps()
            cond_reg_deps = expd_lo.reg_deps() | expd_hi.reg_deps()

            data_ao = SimActionObject(data, reg_deps=data_reg_deps, tmp_deps=data_tmp_deps)
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(condition, reg_deps=cond_reg_deps, tmp_deps=cond_tmp_deps)
            size_ao = SimActionObject(data.length)

            a = SimActionData(self.state, self.state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
            self.state.memory.store(addr.expr, data, condition=condition, endness=self.stmt.endness, action=a)
            self.actions.append(a)
        else:
            # translate the expected value
            expd_lo = self._translate_expr(self.stmt.expdLo)

            # read the old values
            old_lo = self.state.memory.load(addr.expr, len(expd_lo.expr)/8, endness=self.stmt.endness)
            self.state.scratch.store_tmp(self.stmt.oldLo, old_lo)

            # the write data
            data = self._translate_expr(self.stmt.dataLo)

            # do it
            data_ao = SimActionObject(data.expr, reg_deps=data.reg_deps(), tmp_deps=data.tmp_deps())
            addr_ao = SimActionObject(addr.expr, reg_deps=addr.reg_deps(), tmp_deps=addr.tmp_deps())
            guard_ao = SimActionObject(old_lo == expd_lo.expr, reg_deps=expd_lo.reg_deps(), tmp_deps=expd_lo.tmp_deps())
            size_ao = SimActionObject(data.size_bits())

            a = SimActionData(self.state, self.state.memory.id, SimActionData.WRITE, addr=addr_ao, data=data_ao, condition=guard_ao, size=size_ao)
            self.state.memory.store(addr.expr, data.expr, condition=old_lo == expd_lo.expr, endness=self.stmt.endness, action=a)

from ...s_action import SimActionData
from ...s_action_object import SimActionObject
