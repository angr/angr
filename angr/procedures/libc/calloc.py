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
        plugin = self.state.get_plugin('libc')

        self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))

        if self.state.solver.symbolic(sim_nmemb):
            # TODO: find a better way
            nmemb = self.state.solver.max_int(sim_nmemb)
        else:
            nmemb = self.state.solver.eval(sim_nmemb)

        if self.state.solver.symbolic(sim_size):
            # TODO: find a better way
            size = self.state.solver.max_int(sim_size)
        else:
            size = self.state.solver.eval(sim_size)

        final_size = size * nmemb
        if final_size > plugin.max_variable_size:
            final_size = plugin.max_variable_size

        addr = plugin.heap_location
        plugin.heap_location += final_size
        v = self.state.solver.BVV(0, final_size * 8)
        self.state.memory.store(addr, v)

        return addr
