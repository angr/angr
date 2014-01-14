import simuvex

######################################
# open
######################################

class open(simuvex.SimProcedure):
	def __init__(self, ret_expr): # pylint: disable=W0231
		# TODO: Symbolic fd
		path = self.get_arg_value(0)
		mode = self.get_arg_value(1)
		plugin = self.state['posix']

		# TODO handle errors and symbolic path
		fd = plugin.open(path.expr, mode.expr)
		self.set_return_expr(simuvex.SimValue(fd).expr)
		self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
