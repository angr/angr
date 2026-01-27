from __future__ import annotations
import claripy

import angr


class isprint(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_printable = claripy.And(c >= 32, c <= 126)
        return claripy.If(
            is_printable, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"])
        )
