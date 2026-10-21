from __future__ import annotations

from cle.backends.externs.simdata.io_file import io_file_data_for_arch

import angr

from .vprintf import as_return, unmodeled_format_length


class vfprintf(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, file_ptr, fmt, ap):
        fd_offset = io_file_data_for_arch(self.state.arch)["fd"]
        fileno = self.state.mem[file_ptr + fd_offset :].int.resolved
        simfd = self.state.posix.get_fd(fileno)
        if simfd is None:
            return -1
        length = unmodeled_format_length(self, fmt)
        simfd.write(fmt, length)
        return as_return(self, length)


class __vfprintf_chk(vfprintf):
    def run(self, file_ptr, flag, fmt, ap):  # type:ignore[reportIncompatibleMethodOverride] # pylint:disable=arguments-differ,unused-argument
        return super().run(file_ptr, fmt, ap)
