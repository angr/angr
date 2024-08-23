from __future__ import annotations
import claripy

import angr


class fork(angr.SimProcedure):
    def run(self):
        return claripy.If(
            claripy.BoolS("fork_parent"),
            claripy.BVV(1338, self.arch.sizeof["int"]),
            claripy.BVV(0, self.arch.sizeof["int"]),
        )
