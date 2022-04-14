import angr

######################################
# recvfrom
######################################

class recvfrom(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fd, dst, length, flags, src_addr, addrlen):
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        return simfd.read(dst, length)
