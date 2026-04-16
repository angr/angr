from __future__ import annotations
import claripy

import angr


class iscntrl(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_low_ctrl = claripy.And(c >= 0, c <= 31)
        is_del = c == 127
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(
            claripy.Or(is_low_ctrl, is_del),
            claripy.BVV(1, int_size),
            claripy.BVV(0, int_size),
        )
