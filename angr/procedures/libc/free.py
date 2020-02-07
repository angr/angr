import angr
from angr.sim_type import SimTypeTop

######################################
# free
######################################
class free(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr):
        return self.state.heap._free(ptr)
