from __future__ import annotations
import claripy

from ..java import JavaSimProcedure


class NextInt(JavaSimProcedure):
    __provides__ = (("java.util.Random", "nextInt(int)"),)

    def run(self, obj, bound):  # pylint: disable=arguments-differ,unused-argument
        rand = claripy.BVS("rand", 32)
        self.state.solver.add(rand.UGE(0))
        self.state.solver.add(rand.ULT(bound))
        return rand
