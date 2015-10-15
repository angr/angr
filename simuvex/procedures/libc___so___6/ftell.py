import simuvex

from . import _IO_FILE

######################################
# ftell
######################################

class ftell(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr):

        fd_offset = _IO_FILE[self.state.arch.name]['fd']
        fd = self.state.mem[file_ptr + fd_offset : ].int.resolved

        return self.state.posix.pos(fd)
