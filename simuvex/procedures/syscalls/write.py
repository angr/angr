import simuvex
import symexec

######################################
# write
######################################

class write(simuvex.SimProcedure):
	def __init__(self, ret_expr):
		# TODO: Symbolic fd
		fd = self.get_arg_value(0)
		sim_src = self.get_arg_value(1)
		sim_length = self.get_arg_value(2)
		plugin = self.state['posix']

		if sim_length.is_symbolic():
			# TODO improve this
			length = sim_length.max_value()
			if length > self.max_length:
				length = self.max_length
		else:
			length = sim_length.any()

		## TODO handle errors
		data = self.state.mem_expr(sim_src, length)
		length = plugin.write(fd.expr, data, length)

		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src,
						 data, length, (), ()))


		self.set_return_expr(sim_length.expr)
		self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
