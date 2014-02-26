import simuvex
import symexec as se

######################################
# Returns a valid char
######################################

import itertools
char_count = itertools.count()

class ReturnChar(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        s_var = se.BitVec("char_ret_%d" % char_count.next(), self.state.arch.bits)
        self.state.add_constraints(se.And(se.ULE(s_var, 126), se.UGE(s_var, 9)))
        self.exit_return(s_var)
