import angr
from angr.sim_type import SimTypeLength, SimTypeArray, SimTypeTop

######################################
# calloc
######################################

class calloc(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, sim_nmemb, sim_size):
        return self.state.heap._calloc(sim_nmemb, sim_size)
