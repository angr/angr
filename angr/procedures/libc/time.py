import angr
import time as _time

class time(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, time_ptr):
        ts = int(_time.time())
        if self.state.solver.eval(time_ptr) != 0:
            ts_bv = self.state.solver.BVV(ts, 64).reversed
            self.state.memory.store(time_ptr, ts_bv)
        return ts
