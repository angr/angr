from __future__ import annotations
import claripy

import angr


class isupper(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_upper = claripy.And(c >= 65, c <= 90)
        return claripy.If(is_upper, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"]))
