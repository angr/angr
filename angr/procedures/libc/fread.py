from __future__ import annotations
import claripy
from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr


class fread(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, dst, size, nm, file_ptr):
        # TODO handle errors

        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fd = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1

        ret = simfd.read(dst, size * nm)

        # avoid ClaripyZeroDivisionError for size == 0 (If will yield 0 either way)
        return claripy.If(claripy.Or(size == 0, nm == 0), 0, ret // (size + (size == 0)))


fread_unlocked = fread
