from __future__ import annotations

import angr
from angr import claripy


class tolower(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        return claripy.If(claripy.And(c >= 65, c <= 90), c + 32, c)  # A - Z
