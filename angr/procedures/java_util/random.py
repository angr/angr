from ..java import JavaSimProcedure
from angr.engines.soot.values.thisref import SimSootValue_ThisRef
from angr.engines.soot.values.instancefieldref import SimSootValue_InstanceFieldRef
import logging

import claripy

class NextInt(JavaSimProcedure):

    __provides__ = (
        ("java.util.Random", "nextInt(int)"),
    )

    def run(self, obj, bound):
        rand = self.state.solver.BVS('rand', 32)
        self.state.solver.add(rand.UGE(0))
        self.state.solver.add(rand.ULT(bound))
        return rand
