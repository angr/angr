from ..java import JavaSimProcedure
from angr.engines.soot.values.instancefieldref import SimSootValue_InstanceFieldRef
import logging

import claripy

l = logging.getLogger('angr.procedures.java.string.equals')


class StringEquals(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "equals(java.lang.Object)"),
    )

    def run(self, this, str_2):
        l.debug("Called SimProcedure java.string.equals with args: %r, %r", this, str_2)
        str_1_value_ref = SimSootValue_InstanceFieldRef(this.heap_alloc_id, this.type, "value", this.type)
        str_2_value_ref = SimSootValue_InstanceFieldRef(str_2.heap_alloc_id, str_2.type, "value", str_2.type)
        str_1_value = self.state.memory.load(str_1_value_ref)
        str_2_value = self.state.memory.load(str_2_value_ref)
        return claripy.If(str_1_value == str_2_value, claripy.BVV(1, 32), claripy.BVV(0, 32))
