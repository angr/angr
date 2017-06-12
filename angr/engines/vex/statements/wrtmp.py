from . import SimIRStmt, SimStatementError

class SimIRStmt_WrTmp(SimIRStmt):
    def _execute(self):
        # get data and track data reads
        data = self._translate_expr(self.stmt.data)
        self.state.scratch.store_tmp(self.stmt.tmp, data.expr, data.reg_deps(), data.tmp_deps(),
                                     action_holder=self.actions
                                     )

        actual_size = data.size_bits()
        expected_size = self.stmt.data.result_size(self.state.scratch.tyenv)
        if actual_size != expected_size:
            raise SimStatementError("WrTmp expected length %d but got %d" % (actual_size, expected_size))
