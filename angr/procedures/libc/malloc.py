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
        return self.state.heap._malloc(sim_size)
