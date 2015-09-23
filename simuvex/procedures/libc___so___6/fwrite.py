import simuvex

######################################
# fwrite
######################################

class fwrite(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, size, nmemb, file_ptr):
        # TODO handle errors
        data = self.state.memory.load(src, size * nmemb, endness="Iend_BE")
        if self.state.arch.bits == 64:
            offset = 0x70
        else:
            offset = 0x38
        fileno = self.state.mem[file_ptr + offset:].int.resolved
        written = self.state.posix.write(fileno, data, size*nmemb)

        return written
