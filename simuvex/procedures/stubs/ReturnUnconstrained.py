import simuvex

######################################
# Returns an unconstrained byte
######################################

class ReturnUnconstrained(simuvex.SimProcedure):
	def analyze(self, name=None, resolves=None): #pylint:disable=arguments-differ
		self._name = name
		self.resolves = resolves

		return self.state.BV("unconstrained_ret", self.state.arch.bits)

	def __repr__(self):
		return 'ReturnUnconstrained[Pseudo %s - resolves %s]' % (self._name, self.resolves)
