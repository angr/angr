from __future__ import annotations

import angr
from angr import claripy


class toupper(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        return claripy.If(claripy.And(c >= 97, c <= 122), c - 32, c)  # a - z
