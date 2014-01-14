import simuvex

######################################
# free
######################################
class free(simuvex.SimProcedure):
	def __init__(self):
		simuvex.SimProcedure.__init__(self, convention='cdecl')
		if isinstance(self.state.arch, simuvex.SimAMD64):
			# TODO: if the return address cannot be concretized?
			self.exit_return()
		else:
			raise Exception("Architecture %s is not supported yet." % self.state.arch)
