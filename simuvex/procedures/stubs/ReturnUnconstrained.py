import simuvex

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(simuvex.SimProcedure):
    def __init__(self, name=None): # pylint: disable=W0231,
        self._name = name
        self.ret(self.state.BV("unconstrained_ret", self.state.arch.bits))

    def __repr__(self):
        return 'ReturnUnconstrained[Pseudo %s]' % self._name