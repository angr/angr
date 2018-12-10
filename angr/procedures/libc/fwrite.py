import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

######################################
# fwrite
######################################

class fwrite(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, src, size, nmemb, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1
        try:
            return simfd.write(src, size*nmemb)
        except angr.SimUnsatError:
            # XXX: hase fallback
            return 0
