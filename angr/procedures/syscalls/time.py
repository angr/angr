import simuvex

class time(simuvex.SimProcedure):
    IS_SYSCALL = True
    KEY = 'sys_last_time'

    @property
    def last_time(self):
        return self.state.procedure_data.global_variables.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.procedure_data.global_variables[self.KEY] = v

    def run(self, pointer):
        result = self.state.se.BVS('sys_time', self.state.arch.bits)
        if self.last_time is not None:
            self.state.add_constraints(result >= self.last_time)
        self.last_time = result
        return result
