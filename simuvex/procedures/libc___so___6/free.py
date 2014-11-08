import simuvex
from simuvex.s_type import SimTypeTop

######################################
# free
######################################
class free(simuvex.SimProcedure):
    def analyze(self):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        return self.state.se.Unconstrained('free', self.state.arch.bits)
