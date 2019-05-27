import angr
from angr.sim_type import SimTypeTop

######################################
# free
######################################
class free(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr):
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        return self.state.heap._free(ptr)
