from __future__ import annotations
import claripy

import angr


class isalnum(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_upper = claripy.And(c >= 65, c <= 90)
        is_lower = claripy.And(c >= 97, c <= 122)
        is_digit = claripy.And(c >= 48, c <= 57)
        return claripy.If(
            claripy.Or(is_upper, is_lower, is_digit),
            claripy.BVV(1, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
