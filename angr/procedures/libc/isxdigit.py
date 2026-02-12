from __future__ import annotations
import claripy

import angr


class isxdigit(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_digit = claripy.And(c >= 48, c <= 57)
        is_upper_hex = claripy.And(c >= 65, c <= 70)
        is_lower_hex = claripy.And(c >= 97, c <= 102)
        return claripy.If(
            claripy.Or(is_digit, is_upper_hex, is_lower_hex),
            claripy.BVV(1, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
