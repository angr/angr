from __future__ import annotations
import claripy

import angr


class isupper(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_upper = claripy.And(c >= 65, c <= 90)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(is_upper, claripy.BVV(1, int_size), claripy.BVV(0, int_size))
