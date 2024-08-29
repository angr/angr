from __future__ import annotations
import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


class fputs(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, str_addr, file_ptr):
        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1

        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        p_strlen = self.inline_call(strlen, str_addr)
        simfd.write(str_addr, p_strlen.max_null_index)
        return 1


fputs_unlocked = fputs
