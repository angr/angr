from __future__ import annotations
import angr

from ...storage.file import Flags
from .fstat import fstat


class stat(fstat):
    def run(self, p_addr, stat_buf):
        # open temporary fd
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        p_strlen = self.inline_call(strlen, p_addr)
        p_expr = self.state.memory.load(p_addr, p_strlen.max_null_index, endness="Iend_BE")
        file_path = self.state.solver.eval(p_expr, cast_to=bytes)
        fd = self.state.posix.open(file_path, Flags.O_RDONLY)

        # Use fstat to get the result and everything
        result = super().run(fd, stat_buf)

        # close temporary fd
        self.state.posix.close(fd)

        return result
