import simuvex

######################################
# write
######################################

class fwrite(simuvex.SimProcedure):
	def __init__(self):
		sim_src = self.get_arg_value(0)
		sim_length = self.get_arg_value(1)
		sim_num = self.get_arg_value(2)
		fd = self.get_arg_expr(3)

		# to support symbolic length, we would have to support symbolic memory writes
		length = min(sim_length.max() * sim_num.max(), 1024)

		## TODO handle errors
		if length > 0:
			data = self.state.mem_expr(sim_src, length)
			length = self.state['posix'].write(fd, data, length)
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src, data, length, (), ()))

		self.exit_return(sim_length.expr)
