from __future__ import annotations
import claripy

import angr


class islower(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_lower = claripy.And(c >= 97, c <= 122)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(is_lower, claripy.BVV(1, int_size), claripy.BVV(0, int_size))
