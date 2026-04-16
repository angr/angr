from __future__ import annotations
import claripy

import angr


class isalpha(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_upper = claripy.And(c >= 65, c <= 90)
        is_lower = claripy.And(c >= 97, c <= 122)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(
            claripy.Or(is_upper, is_lower),
            claripy.BVV(1, int_size),
            claripy.BVV(0, int_size),
        )
