import simuvex

######################################
# __isoc99_scanf
######################################

class __isoc99_scanf(simuvex.SimProcedure):
    def __init__(self):
        # TODO: Access different registers on different archs
        # TODO: handle symbolic and static modes
        fd = 0 # always stdin
        fmt_str = self.get_arg_value(0)
        # TODO: Now we assume it's always '%s'
        sim_dst = self.get_arg_value(1)
        length = 17 # TODO: Symbolic length
        plugin = self.state['posix']

        for i in range(0, length):
            data = plugin.read(fd, 1)
            self.state.store_mem(sim_dst.expr + i, data)

        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, self.state.expr_value(data), length, [], [], [], []))

        self.exit_return(sim_dst.expr)
