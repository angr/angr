import simuvex
import symexec
import itertools
######################################
# malloc
######################################

malloc_mem_counter = itertools.count()
heap_id = 'heap'
max_mem_allocable_per_variable = 2 ** 16

class malloc(simuvex.SimProcedure):
        def __init__(self):
                #TODO add convention
                simuvex.SimProcedure.__init__(self)
                if isinstance(self.state.arch, simuvex.SimAMD64):
                        sim_size = simuvex.SimValue(self.get_arg_expr(0))
                        if sim_size.is_symbolic():
                                #TODO: find a better way
                                size = sim_size.max() * 8
                                if size > max_mem_allocable_per_variable:
                                        size = max_mem_allocable_per_variable
                        else:
                                size = sim_size.any() * 8

                        addr = self.state.get_plugin('libc').heap_location
                        self.state.get_plugin('libc').heap_location += size
                        mem_id = "%s_%x_%d" % (heap_id, addr, malloc_mem_counter.next())
                        v = symexec.BitVec(mem_id, size)
                        self.state.store_mem(addr, v)

                        #TODO: also SimMemRef??
                        #ask idx???
                        self.exit_return(addr)
                else:
                        raise Exception("Architecture %s is not supported yet." % self.state.arch)
