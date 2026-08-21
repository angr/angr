from __future__ import annotations

import angr
from angr import claripy


class isdigit(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_digit = claripy.And(c >= 48, c <= 57)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(is_digit, claripy.BVV(1, int_size), claripy.BVV(0, int_size))
