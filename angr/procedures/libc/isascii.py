from __future__ import annotations
import claripy

import angr


class isascii(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_ascii = claripy.And(c >= 0, c <= 127)
        return claripy.If(is_ascii, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"]))
