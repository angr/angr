import angr

class time(angr.SimProcedure):
    KEY = 'sys_last_time'

    @property
    def last_time(self):
        return self.state.globals.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.globals[self.KEY] = v

    def run(self, pointer):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            ts = int(_time.time())
            if self.state.solver.eval(time_ptr) != 0:
                ts_bv = self.state.solver.BVV(ts, 64)
                self.state.memory.store(time_ptr, ts_bv, endness=self.state.arch.memory_endness)
            return ts_bv
        else:
            result = self.state.solver.BVS('sys_time', self.state.arch.bits, key=('api', 'time'))
            if self.last_time is not None:
                self.state.add_constraints(result >= self.last_time)
            self.last_time = result
            return result
