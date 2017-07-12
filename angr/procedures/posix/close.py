import angr

######################################
# close
######################################

class close(angr.SimProcedure):
    def run(self, fd):  # pylint:disable=arguments-differ

        self.state.posix.close(fd)

        return self.state.se.BVV(0, self.state.arch.bits)
