import angr

######################################
# send
######################################

class send(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, src, length):
        data = self.state.memory.load(src, length)
        length = self.state.posix.write(fd, data, length)
        return length
