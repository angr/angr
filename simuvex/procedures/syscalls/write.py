import simuvex
import symexec

######################################
# write
######################################

class write(simuvex.SimProcedure):
        def __init__(self):
                import ipdb;ipdb.set_trace()
                # TODO: Symbolic fd
                fd = self.get_arg_value(0)
                sim_src = self.get_arg_value(1)
                sim_length = self.get_arg_value(2)
                plugin = self.state.plugin('posix')

                if sim_length.is_symbolic():
                        # TODO improve this
                        length = sim_length.max_value()
                        if length > self.max_length:
                                length = self.max_length
                else:
                        length = sim_length.any()

                ## TODO handle errors
                data = self.state.mem_expr(sim_src, length)
                length = plugin.write(dst, data, length)

                self.add_refs(simuvex.SimMemRead(self.addr_from, self.stmt_from, simuvex.SimValue(sim_dst),
                                                  simuvex.SimValue(data), length, (), ()))


                self.set_return_expr(sim_length.expr)
                self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
