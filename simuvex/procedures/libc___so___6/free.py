import simuvex
from simuvex.s_type import SimTypeTop

######################################
# free
######################################
class free(simuvex.SimProcedure):
    def analyze(self):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        self.ret()
