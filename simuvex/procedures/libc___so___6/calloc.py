import simuvex
from simuvex.s_type import SimTypeLength, SimTypePointer, SimTypeArray, SimTypeTop
import symexec
import itertools

######################################
# calloc
######################################

calloc_mem_counter = itertools.count()

class calloc(simuvex.SimProcedure):
        def __init__(self):
                self.argument_types = {0: SimTypeLength(self.state.arch),
                                       1: SimTypeLength(self.state.arch)}

                plugin = self.state.get_plugin('libc')

                sim_nmemb = self.get_arg_value(0)
                sim_size = self.get_arg_value(1)

                self.return_type = self.ty_ptr(SimTypeArray(SimTypeTop(sim_size), sim_nmemb))

                if sim_nmemb.is_symbolic():
                        # TODO: find a better way
                        nmemb = sim_nmemb.max()
                else:
                        nmemb = sim_nmemb.any()

                if sim_size.is_symbolic():
                        # TODO: find a better way
                        size = sim_size.max()
                else:
                        size = sim_size.any()

                final_size = size * nmemb * 8
                if final_size > plugin.max_variable_size:
                        final_size = plugin.max_variable_size

                addr = plugin.heap_location
                plugin.heap_location += final_size
                v = symexec.BitVecVal(0, final_size)
                self.state.store_mem(addr, v)

                self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, simuvex.SimValue(addr), 
                                                  simuvex.SimValue(v), final_size, [], [], [], []))

                self.exit_return(addr)
