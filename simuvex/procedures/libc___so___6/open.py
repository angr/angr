import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt, SimTypeFd

######################################
# open
######################################

class open(simuvex.SimProcedure): #pylint:disable=W0622
	#pylint:disable=arguments-differ

	def run(self, path, flags):
		self.argument_types = {0: self.ty_ptr(SimTypeString()),
							   1: SimTypeInt(32, True)}
		self.return_type = SimTypeFd()

		fd = self.state.posix.open(path, flags)
		return fd
