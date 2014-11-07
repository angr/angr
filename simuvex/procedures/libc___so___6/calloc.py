import simuvex
from simuvex.s_type import SimTypeLength, SimTypeArray, SimTypeTop

######################################
# calloc
######################################

class calloc(simuvex.SimProcedure):
    def __init__(self): #pylint:disable=W0231
        self.argument_types = { 0: SimTypeLength(self.state.arch),
                                1: SimTypeLength(self.state.arch)}
        plugin = self.state.get_plugin('libc')

        sim_nmemb = self.arg(0)
        sim_size = self.arg(1)

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
        v = self.state.BVV(0, final_size)
        self.state.store_mem(addr, v)

        self.ret(addr)
