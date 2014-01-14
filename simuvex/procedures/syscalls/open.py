import simuvex

######################################
# open
######################################

class open(simuvex.SimProcedure):
	def __init__(self, ret_expr): # pylint: disable=W0231
		# TODO: Symbolic fd
		path = self.get_arg_value(0)
		flags = self.get_arg_value(1)
                # TODO handle mode if flags == O_CREAT

		plugin = self.state['posix']

		# TODO handle errors and symbolic path
		fd = plugin.open(path.expr, flags.expr)
		self.set_return_expr(simuvex.SimValue(fd).expr)
		self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
