import angr
import time as _time


class time(angr.SimProcedure):
    # pylint: disable=arguments-differ
    KEY = "sys_last_time"

    @property
    def last_time(self):
        return self.state.globals.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.globals[self.KEY] = v

    def run(self, pointer):
        # TODO lord have mercy. how big is time_t?
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            ts = int(_time.time())
            result = self.state.solver.BVV(ts, self.state.arch.bits)
        else:
            result = self.state.solver.BVS("sys_time", self.state.arch.bits, key=("api", "time"))
            if self.last_time is not None:
                self.state.add_constraints(result.SGE(self.last_time))
            else:
                self.state.add_constraints(result.SGE(0))
            self.last_time = result
        self.state.memory.store(pointer, result, condition=(pointer != 0))
        return result
