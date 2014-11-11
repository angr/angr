import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def analyze(self, fd, src, length):
        data = self.state.mem_expr(src, length)
        length = self.state.posix.write(fd, data, length)
        return length
