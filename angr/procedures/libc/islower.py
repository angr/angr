from __future__ import annotations
import claripy

import angr


class islower(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_lower = claripy.And(c >= 97, c <= 122)
        return claripy.If(is_lower, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"]))
