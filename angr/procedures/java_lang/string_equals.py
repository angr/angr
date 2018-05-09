from ..java import JavaSimProcedure
import  logging

import claripy

l = logging.getLogger('angr.procedures.java.string.equals')

class StringEquals(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "equals(java.lang.Object)"),
    )

    def run(self, str_1, str_2):
        l.debug("Called SimProcedure java.string.equals with args: %s (%r), %s (%r)", str_1, str_1, str_2, str_2)
        str_1 = str_1 if "String" in str_1.__class__.__name__ else self.state.memory.load(str_1)
        str_2 = str_2 if "String" in str_2.__class__.__name__ else self.state.memory.load(str_2)
        result = claripy.If(str_1 == str_2, claripy.BVV(1, 32), claripy.BVV(0, 32))
        return result
