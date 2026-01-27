from __future__ import annotations
import claripy

import angr


class isgraph(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, c):
        is_graph = claripy.And(c >= 33, c <= 126)
        return claripy.If(is_graph, claripy.BVV(1, self.arch.sizeof["int"]), claripy.BVV(0, self.arch.sizeof["int"]))
