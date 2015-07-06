import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags): #pylint:disable=unused-argument
        data = self.state.posix.read(fd, length)
        self.state.memory.store(dst, data)
        return length
