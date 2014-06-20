import simuvex

######################################
# read
######################################

class read(simuvex.SimProcedure):
        def __init__(self, ret_expr = None): # pylint: disable=W0231
                # TODO: Symbolic fd
                fd = self.get_arg_value(0)
                sim_dst = self.get_arg_value(1)
                sim_length = self.get_arg_value(2)
                plugin = self.state['posix']

                if sim_length.is_symbolic():
                        # TODO improve this
                        length = sim_length.max_value()
                        if length > plugin.max_length:
                                length = plugin.max_length
                else:
                        length = sim_length.any()

                # TODO handle errors
                data = plugin.read(fd.expr, length)
                self.state.store_mem(sim_dst.expr, data)
                self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, data, length, [], [], [], []))

                self.set_return_expr(sim_length.expr)
                if self.read_expr is not None:
                        self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
