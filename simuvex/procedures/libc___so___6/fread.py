import simuvex

from . import _IO_FILE

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = _IO_FILE[self.state.arch.name]['fd']
        fd = self.state.mem[file_ptr + fd_offset:].int.resolved
        ret = self.state.posix.read(fd, dst, size * nm)
        return self.state.se.If(self.state.se.Or(size == 0, nm == 0), 0, ret / size)
