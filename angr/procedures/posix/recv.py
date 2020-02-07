import angr
from angr.sim_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# recv
######################################

class recv(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd, dst, length, flags):  # pylint:disable=unused-argument
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        return simfd.read(dst, length)
