import simuvex

from . import _IO_FILE

######################################
# fwrite
######################################

class fwrite(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, size, nmemb, file_ptr):
        # TODO handle errors
        data = self.state.memory.load(src, size * nmemb, endness="Iend_BE")
        fd_offset = _IO_FILE[self.state.arch.name]['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        written = self.state.posix.write(fileno, data, size*nmemb)

        return written
