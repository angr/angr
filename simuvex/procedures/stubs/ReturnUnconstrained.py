import simuvex
import symexec as se

######################################
# Returns an unconstrained byte
######################################

import itertools
unconstrained_count = itertools.count()

class ReturnUnconstrained(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        self.exit_return(se.BitVec("unconstrained_ret_%d" % unconstrained_count.next(), self.state.arch.bits))
