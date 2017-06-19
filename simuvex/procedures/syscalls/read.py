import simuvex

######################################
# read
######################################

class read(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, dst, length):
        self.state.posix.read(fd, dst, length)
        return length
