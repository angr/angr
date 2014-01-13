import simuvex
import symexec
import itertools
######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
        def __init__(self):
            simuvex.SimProcedure.__init__(self, convention='cdecl')
            if isinstance(self.state.arch, simuvex.SimAMD64):
                size = self.get_arg_expr(0)
                
                #TODO symbolic size!
                addr = self.state.plugin('libc').heap_location
                self.state.plugin('libc').heap_location += size
                mem_id = "%x_%d" % (addr, malloc_mem_counter.next())
                v = symexec.BitVec(mem_id, size)
                self.state.store_mem(addr, v)

                self.set_return_expr(addr)
                ret_target = self.do_return()

                #TODO: also SimMemRef??
                #ask idx???

                self.add_exit(SimExit(expr=ret_target, state=self.state))
            else:
                raise Exception("Architecture %s is not supported yet." % self.state.arch)
