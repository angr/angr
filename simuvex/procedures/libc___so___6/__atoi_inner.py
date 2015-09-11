import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class __atoi_inner(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, s, region):
        #pylint:disable=attribute-defined-outside-init

        max_symbolic_bytes = self.state.libc.buf_symbolic_bytes
        max_str_len = self.state.libc.max_str_len

        # TODO support of sign prefixes '+' and '-'
        # TODO support for strings longer than a byte
        char = region.load(s, 1)
        char = char.zero_extend(self.state.arch.bits - 8)

        lower_bound = self.state.BVV('0')
        lower_bound = lower_bound.zero_extend(self.state.arch.bits - 8)

        upper_bound = self.state.BVV('9')
        upper_bound = upper_bound.zero_extend(self.state.arch.bits - 8)


        expression = self.state.se.And(char >= lower_bound, \
                        char <= upper_bound)
        result = self.state.se.If(expression, char - lower_bound, self.state.BVV(0))

        return result
