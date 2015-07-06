import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        data = self.state.posix.read(fd, self.state.se.any_int(length))
        self.state.memory.store(dst, data)
        return length
