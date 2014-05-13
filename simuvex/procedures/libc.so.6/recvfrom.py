import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        fd = self.get_arg_value(0)
        sim_dst = self.get_arg_value(1)
        plugin = self.state['posix']

        # TODO: Now it's limiting UDP package to 25 bytes
        # We need to better handling for this
        length = 40

        # TODO handle errors
        data = plugin.read(fd.expr, length)
        self.state.store_mem(sim_dst.expr, data)
        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, self.state.expr_value(data), length, [], [], [], []))

        self.exit_return(simuvex.SimValue(length).expr)
