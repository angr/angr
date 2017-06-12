import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    def run(self, fd):  # pylint:disable=arguments-differ

        self.state.posix.close(fd)

        return self.state.se.BVV(0, self.state.arch.bits)
