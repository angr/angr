import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd):
        self.state.posix.close(fd)
        v = self.state.BVV(0, self.state.arch.bits)
        return v
