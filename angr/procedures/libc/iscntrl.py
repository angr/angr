from __future__ import annotations
import claripy

import angr


class iscntrl(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_low_ctrl = claripy.And(c >= 0, c <= 31)
        is_del = c == 127
        return claripy.If(
            claripy.Or(is_low_ctrl, is_del),
            claripy.BVV(1, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
