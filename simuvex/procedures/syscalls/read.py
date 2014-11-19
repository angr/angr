import simuvex

######################################
# read
######################################

class read(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        data = self.state.posix.read(fd, length)
        self.state.store_mem(dst, data)
        return length
