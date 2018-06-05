import angr

######################################
# read
######################################

class read(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        try:
            simfd = self.state.posix.get_fd(fd)
            if simfd is None:
                return -1

            return simfd.read(dst, length)
        except angr.SimUnsatError:
            return self.state.solver.Unconstrained('read', 32, uninitialized=False)
