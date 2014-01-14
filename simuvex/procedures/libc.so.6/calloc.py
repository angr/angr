import simuvex
import symexec
import itertools

######################################
# calloc
######################################

calloc_mem_counter = itertools.count()
#TODO move them in a shared location
heap_id = 'heap'
max_mem_allocable_per_variable = 2 ** 16

class calloc(simuvex.SimProcedure):
        def __init__(self):
                #add convention
                simuvex.SimProcedure.__init__(self)
                if isinstance(self.initial_state.arch, simuvex.SimAMD64):
                        sim_nmemb = simuvex.SimValue(self.get_arg_expr(0))
                        sim_size = simuvex.SimValue(self.get_arg_expr(1))

                        if sim_nmemb.is_symbolic():
                                #TODO: find a better way
                                nmemb = sim_nmemb.max()
                        else:
                                nmemb = sim_nmemb.any()

                        if sim_size.is_symbolic():
                                #TODO: find a better way
                                size = sim_size.max()
                        else:
                                size = sim_size.any()

                        final_size = size * nmemb * 8
                        if final_size > max_mem_allocable_per_variable:
                                final_size = max_mem_allocable_per_variable

                        addr = self.initial_state.get_plugin('libc').heap_location
                        self.initial_state.get_plugin('libc').heap_location += final_size
                        v = symexec.BitVecVal(0, final_size)
                        self.state.store_mem(addr, v)
                        #TODO: also SimMemRef??
                        #ask idx???
                        self.exit_return(addr)

                else:
                        raise Exception("Architecture %s is not supported yet." % self.initial_state.arch)
