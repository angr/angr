from . import SimIRStmt, SimStatementError

class SimIRStmt_WrTmp(SimIRStmt):
    def _execute(self):
        # get data and track data reads
        data = self._translate_expr(self.stmt.data)
        self._write_tmp(self.stmt.tmp, data.expr, data.size_bits(), data.reg_deps(), data.tmp_deps())

        actual_size = data.size_bits()
        expected_size = self.stmt.data.result_size
        if actual_size != expected_size:
            raise SimStatementError("WrTmp expected length %d but got %d" % (actual_size, expected_size))
