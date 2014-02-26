import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
	def __init__(self, ret_expr = None):
		fd = self.get_arg_expr(0)
		sim_src = self.get_arg_value(1)
		sim_length = self.get_arg_value(2)

		# to support symbolic length, we would have to support symbolic memory writes
		length = sim_length.max()

		## TODO handle errors
		data = self.state.mem_expr(sim_src, length)
		length = self.state['posix'].write(fd, data, length)

		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src, data, length, (), ()))
		self.set_return_expr(sim_length.expr)
		if ret_expr is not None:
			self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
