from __future__ import annotations
import claripy

import angr


class isascii(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_ascii = claripy.And(c >= 0, c <= 127)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(is_ascii, claripy.BVV(1, int_size), claripy.BVV(0, int_size))
