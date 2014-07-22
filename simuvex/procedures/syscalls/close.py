import simuvex

######################################
# close
######################################

class close(simuvex.SimProcedure):
	def __init__(self, ret_expr = None): # pylint: disable=W0231
		# TODO: Symbolic fd
		fd = self.arg(0)
		plugin = self.state['posix']

		# TODO handle errors
		plugin.close(fd)

		v = self.state.BVV(0, self.state.arch.bits)
		self.set_return_expr(v)
		# TODO: code referencies?
		if ret_expr is not None:
			self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
