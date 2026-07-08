from __future__ import annotations

import angr
from angr import claripy


# these are NOT suitable for multibyte characters
class CharNextA(angr.SimProcedure):
    def run(self, ptr):
        return claripy.If(self.state.mem[ptr].uint8_t.resolved == 0, ptr, ptr + 1)


class CharPrevA(angr.SimProcedure):
    def run(self, start, ptr):
        return claripy.If(start == ptr, start, ptr - 1)
