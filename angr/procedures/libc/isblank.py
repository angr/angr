from __future__ import annotations
import claripy

import angr


class isblank(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_space = c == 32
        is_tab = c == 9
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(
            claripy.Or(is_space, is_tab),
            claripy.BVV(1, int_size),
            claripy.BVV(0, int_size),
        )
