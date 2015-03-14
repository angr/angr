from . import SimIRStmt

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
            old_cnt = self.state.mem_expr(addr.expr, len(expd_lo.expr)*2/8, endness=self.stmt.endness)
            old_hi, old_lo = old_cnt.chop(bits=len(expd_lo))
            self.state.store_tmp(self.stmt.oldLo, old_lo)
            self.state.store_tmp(self.stmt.oldHi, old_hi)

            # the write data
            data_lo = self._translate_expr(self.stmt.dataLo)
            data_hi = self._translate_expr(self.stmt.dataHi)
            data = self.state.se.Concat(data_hi.expr, data_lo.expr)

            # do it
            self.state.store_mem(addr.expr, data, condition=self.state.se.And(old_lo == expd_lo.expr, old_hi == expd_hi.expr), endness=self.stmt.endness)
        else:
            # translate the expected value
            expd_lo = self._translate_expr(self.stmt.expdLo)

            # read the old values
            old_lo = self.state.mem_expr(addr.expr, len(expd_lo.expr)/8, endness=self.stmt.endness)
            self.state.store_tmp(self.stmt.oldLo, old_lo)

            # the write data
            data = self._translate_expr(self.stmt.dataLo)

            # do it
            self.state.store_mem(addr.expr, data.expr, condition=self.state.se.And(old_lo == expd_lo.expr), endness=self.stmt.endness)

