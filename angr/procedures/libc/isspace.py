from __future__ import annotations
import claripy

import angr


class isspace(angr.SimProcedure):
    # pylint: disable=arguments-differ, missing-class-docstring
    def run(self, c):
        is_space_char = c == 32
        is_tab_to_cr = claripy.And(c >= 9, c <= 13)
        int_size = self.arch.sizeof["int"]  # type: ignore[reportOptionalMemberAccess]

        return claripy.If(
            claripy.Or(is_space_char, is_tab_to_cr),
            claripy.BVV(1, int_size),
            claripy.BVV(0, int_size),
        )
