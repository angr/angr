from __future__ import annotations
import claripy

import angr


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, stream, simfd=None):
        if simfd is None:
            fileno = angr.SIM_PROCEDURES["posix"]["fileno"]
            fd = self.inline_call(fileno, stream).ret_expr
            simfd = self.state.posix.get_fd(fd)

        if simfd is None:
            return -1

        (
            data,
            real_length,
        ) = simfd.read_data(1)
        return claripy.If(real_length == 0, -1, data.zero_extend(self.arch.sizeof["int"] - 8))


getc = fgetc
fgetc_unlocked = fgetc
getc_unlocked = fgetc
