import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags): #pylint:disable=unused-argument
        bytes_recvd = self.state.posix.read(fd, dst, self.state.se.any_int(length))
        return bytes_recvd
