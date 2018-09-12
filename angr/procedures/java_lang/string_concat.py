import logging

import claripy

from ..java import JavaSimProcedure

l = logging.getLogger('angr.procedures.java.string.concat')


class StringConcat(JavaSimProcedure):

    __provides__ = (
        ("java.lang.String", "concat(java.lang.String)"),
    )

    def run(self, str_1, str_2): # pylint: disable=arguments-differ
        l.debug("Called SimProcedure java.string.concat with args: %s (%r), %s (%r)", str_1, str_1, str_2, str_2)
        str_1 = str_1 if "String" in str_1.__class__.__name__ else self.state.memory.load(str_1)
        str_2 = str_2 if "String" in str_2.__class__.__name__ else self.state.memory.load(str_2)
        import ipdb; ipdb.set_trace()
        result = claripy.StrConcat(str_1, str_2)
        return result
