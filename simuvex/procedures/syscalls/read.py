import simuvex
import symexec

######################################
# read
######################################

class read(simuvex.SimProcedure):
        def __init__(self):
                simuvex.SimProcedure.__init__(self, convention='syscall')
                if isinstance(self.state.arch, simuvex.SimAMD64):
                        src = self.get_arg_expr(0)
                        dst = self.get_arg_expr(1)
                        length = self.get_arg_expr(2)
                        
                        #TODO length symbolic value?

                        ## TODO handle errors
                        data = self.state.plugin('posix').read(src, length)
                        self.state.store_mem(dst, data)

                        sim_src = simuvex.SimValue(src)
                        sim_dst = simuvex.SimValue(dst)
                        self.add_refs(simuvex.SimMemRead(sim_src, data, length))
                        self.add_refs(simuvex.SimMemWrite(sim_dst, data, length))
                        #TODO: also SimMemRef??

                        self.exit_return(length)

                else:
                        raise Exception("Architecture %s is not supported yet." % self.state.arch)
