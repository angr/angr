import angr

######################################
# write
######################################

class write(angr.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd, src, length):
        data = self.state.memory.load(src, length)
        length = self.state.posix.write(fd, data, length)
        return length
