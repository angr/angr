import angr
from angr.sim_type import SimTypeLength, SimTypeArray, SimTypeTop

######################################
# calloc
######################################

class calloc(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, sim_nmemb, sim_size):
        self.argument_types = { 0: SimTypeLength(self.state.arch),
                                1: SimTypeLength(self.state.arch)}
        self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))
        return self.state.heap._calloc(sim_nmemb, sim_size)
