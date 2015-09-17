import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")


class atoi(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    @staticmethod
    def _atoi_inner(s, state, region):
        #pylint:disable=attribute-defined-outside-init

        # TODO support of sign prefixes '+' and '-'
        # TODO support for strings longer than a byte
        char = region.load(s, 1)
        char = char.zero_extend(state.arch.bits - 8)

        lower_bound = state.BVV('0')
        lower_bound = lower_bound.zero_extend(state.arch.bits - 8)

        upper_bound = state.BVV('9')
        upper_bound = upper_bound.zero_extend(state.arch.bits - 8)

        expression = state.se.And(char >= lower_bound, \
                        char <= upper_bound)
        result = state.se.If(expression, char - lower_bound, state.BVV(0))

        return (expression, result)

    def run(self, s):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch, True)

        return atoi._atoi_inner(s, self.state, self.state.memory)[1]
