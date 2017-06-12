import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd):
        fd = self.state.se.any_int(fd)

        # Return error if file descriptor does not exist or file is already closed
        if fd not in self.state.posix.files or self.state.posix.files[fd].closed is True:
            v = self.state.se.BVV(-1, self.state.arch.bits)

        # Otherwise close it and return good
        else:
            self.state.posix.close(fd)
            v = self.state.se.BVV(0, self.state.arch.bits)

        return v
