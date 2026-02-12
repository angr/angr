from __future__ import annotations
import claripy

import angr


class isprint(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_printable = claripy.And(c >= 32, c <= 126)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(is_printable, claripy.BVV(1, int_size), claripy.BVV(0, int_size))
