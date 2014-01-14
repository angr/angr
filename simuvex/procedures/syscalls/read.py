import simuvex
import symexec

######################################
# read
######################################

class read(simuvex.SimProcedure):
        def __init__(self):
                # TODO: Symbolic fd
                fd = self.get_arg_value(0)
                sim_dst = self.get_arg_value(1)
                sim_length = self.get_arg_value(2)
                plugin = self.state.plugin('posix')
                
                if sim_length.is_symbolic():
                        # TODO improve this
                        length = sim_length.max_value()
                        if length > plugin.max_length:
                                length = plugin.max_length
                else:
                        length = sim_length.any()

                # TODO handle errors
                data = plugin.read(fd, length)
                self.state.store_mem(sim_dst, data)

                self.add_refs(simuvex.SimMemWrite(self.addr_from, self.stmt_from, simuvex.SimValue(sim_dst), 
                                                  simuvex.SimValue(data), length, [], [], [], []))
                
                self.exit_return(length)
