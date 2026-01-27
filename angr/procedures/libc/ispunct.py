from __future__ import annotations
import claripy

import angr


class ispunct(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_punct_1 = claripy.And(c >= 33, c <= 47)  # ! to /
        is_punct_2 = claripy.And(c >= 58, c <= 64)  # : to @
        is_punct_3 = claripy.And(c >= 91, c <= 96)  # [ to `
        is_punct_4 = claripy.And(c >= 123, c <= 126)  # { to ~
        return claripy.If(
            claripy.Or(is_punct_1, is_punct_2, is_punct_3, is_punct_4),
            claripy.BVV(1, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
