import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length):
        bytes_recvd = self.state.posix.read(fd, dst, self.state.se.any_int(length))
        return bytes_recvd
