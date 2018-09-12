import logging

from ..java import JavaSimProcedure

l = logging.getLogger('angr.procedures.java.string.equals')


class StringEquals(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "equals(java.lang.Object)"),
    )

    def run(self, str_ref_1, str_ref_2): # pylint: disable=unused-argument
        str_1 = self.state.memory.load(str_ref_1)
        str_2 = self.state.memory.load(str_ref_2)
        return self.state.solver.If(str_1 == str_2,
                                    self.state.solver.BVV(1, 32),
                                    self.state.solver.BVV(0, 32))
