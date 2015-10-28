import simuvex
from simuvex.s_type import SimTypeLength, SimTypeArray, SimTypeTop

######################################
# calloc
######################################

class calloc(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sim_nmemb, sim_size):
        self.argument_types = { 0: SimTypeLength(self.state.arch),
                                1: SimTypeLength(self.state.arch)}
        plugin = self.state.get_plugin('libc')

        self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))

        if self.state.se.symbolic(sim_nmemb):
            # TODO: find a better way
            nmemb = self.state.se.max_int(sim_nmemb)
        else:
            nmemb = self.state.se.any_int(sim_nmemb)

        if self.state.se.symbolic(sim_size):
            # TODO: find a better way
            size = self.state.se.max_int(sim_size)
        else:
            size = self.state.se.any_int(sim_size)

        final_size = size * nmemb * 8
        if final_size > plugin.max_variable_size:
            final_size = plugin.max_variable_size

        addr = plugin.heap_location
        plugin.heap_location += final_size
        v = self.state.se.BVV(0, final_size)
        self.state.memory.store(addr, v)

        return addr
