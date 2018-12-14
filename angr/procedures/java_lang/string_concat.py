import logging

import claripy

from ..java import JavaSimProcedure

l = logging.getLogger('angr.procedures.java.string.concat')


class StringConcat(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "concat(java.lang.String)"),
    )

    def run(self, str_1_ref, str_2_ref): # pylint: disable=arguments-differ
        l.debug("Called SimProcedure java.string.concat with args: {} {}".format(str_1_ref, str_2_ref))
        str_1 = self.state.memory.load(str_1_ref)
        str_2 = self.state.memory.load(str_2_ref)
        result = claripy.StrConcat(str_1, str_2)
        return result
