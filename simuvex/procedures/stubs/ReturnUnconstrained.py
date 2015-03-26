import simuvex

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(simuvex.SimProcedure):
    def run(self, name=None, resolves=None): #pylint:disable=arguments-differ
        self._name = name
        self.resolves = resolves

        o = self.state.se.Unconstrained("unconstrained_ret", self.state.arch.bits)
        #if 'unconstrained_ret_9_64' in o.variables:
        #   __import__('ipdb').set_trace()
        return o

    def __repr__(self):
        return 'ReturnUnconstrained[Pseudo %s - resolves %s]' % (self._name, self.resolves)
