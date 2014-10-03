import simuvex

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        string = self.arg(0)

        plugin = self.state['posix']
        self.add_refs(simuvex.SimFileWrite(self.addr, self.stmt_from, 1, plugin.pos(1), string[7:0], 1))
        plugin.write(1, string[7:0], 1)

        # TODO: return values
        self.ret()
