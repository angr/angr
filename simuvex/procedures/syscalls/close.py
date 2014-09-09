import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		fd = self.arg(0)
		plugin = self.state['posix']

		# TODO handle errors
		plugin.close(fd)

		v = self.state.BVV(0, self.state.arch.bits)
		self.ret(v)
		# TODO: code referencies?
