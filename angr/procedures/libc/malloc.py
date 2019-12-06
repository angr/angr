import angr
from angr.sim_type import SimTypeLength, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_size):
        self.argument_types = {0: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeTop(sim_size))
        return self.state.heap._malloc(sim_size)
