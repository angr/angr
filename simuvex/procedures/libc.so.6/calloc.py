import simuvex
import symexec
import itertools

######################################
# calloc
######################################

calloc_mem_counter = itertools.count()

class calloc(simuvex.SimProcedure):
        def __init__(self):
            simuvex.SimProcedure.__init__(self, convention='cdecl')
            if isinstance(self.initial_state.arch, simuvex.SimAMD64):
                nmemb = self.get_arg_expr(0)
                size = self.get_arg_expr(1)

                #TODO symbolic size!
                addr = self.initial_state.plugin('libc').heap_location
                self.initial_state.plugin('libc').heap_location += (size*nmemb)
                v = symexec.BitVecVal(0, size*nmemb)
                self.state.store_mem(addr, v)
                #TODO: also SimMemRef??
                #ask idx???
                self.exit_return(addr)

            else:
                raise Exception("Architecture %s is not supported yet." % self.initial_state.arch)
