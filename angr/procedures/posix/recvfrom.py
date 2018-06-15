import angr

######################################
# recvfrom
######################################

class recvfrom(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags, src_addr, addrlen): #pylint:disable=unused-argument
        bytes_recvd = self.state.posix.read(fd, dst, self.state.se.eval(length))
        return bytes_recvd
