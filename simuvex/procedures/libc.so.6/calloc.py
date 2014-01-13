import simuvex
import symexec
import itertools

######################################
# calloc
######################################

calloc_mem_counter = itertools.count()

class calloc(simuvex.SimProcedure):
        def __init__(self, state, options=None, mode=None):
            simuvex.SimProcedure.__init__(self, state, options=options, mode=mode, convention='syscall')
            if isinstance(self.initial_state.arch, simuvex.SimAMD64):
                nmemb = self.get_arg_expr(0)
                size = self.get_arg_expr(1)

                #TODO symbolic size!
                addr = self.initial_state.plugin('libc').heap_location
                self.initial_state.plugin('libc').heap_location += (size*nmemb)
                v = symexec.BitVecVal(0, size*nmemb)
                self.state.store_mem(addr, v)

                self.set_return_expr(addr)
                ret_target = self.do_return()

                #TODO: also SimMemRef??
                #ask idx???

                self.add_exit(SimExit(expr=ret_target, state=self.initial_state))
            else:
                raise Exception("Architecture %s is not supported yet." % self.initial_state.arch)
