from __future__ import annotations
import claripy

import angr


class isdigit(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_digit = claripy.And(c >= 48, c <= 57)
        return claripy.If(is_digit, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"]))
