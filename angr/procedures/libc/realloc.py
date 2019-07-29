import angr
from angr.sim_type import SimTypeLength, SimTypeTop

######################################
# realloc
######################################

class realloc(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, ptr, size):
        self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
                                1: SimTypeLength(self.state.arch) }
        self.return_type = self.ty_ptr(SimTypeTop(size))
        return self.state.heap._realloc(ptr, size)
