from __future__ import annotations
import claripy

import angr


class isblank(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_space = c == 32
        is_tab = c == 9
        return claripy.If(
            claripy.Or(is_space, is_tab),
            claripy.BVV(1, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
