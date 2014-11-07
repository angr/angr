import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    def analyze(self):
        # TODO: Symbolic fd
        fd = self.arg(0)
        plugin = self.state['posix']

        # TODO handle errors
        plugin.close(fd)

        v = self.state.BVV(0, self.state.arch.bits)
        self.ret(v)
        # TODO: code referencies?
