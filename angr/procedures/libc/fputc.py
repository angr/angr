from __future__ import annotations
import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fputc(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, c, file_ptr):
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        simfd.write_data(c[7:0])
        return c & 0xFF


putc = fputc
fputc_unlocked = fputc
putc_unlocked = fputc
