import simuvex

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        self.exit_return(self.state.BV("unconstrained_ret", self.state.arch.bits))
