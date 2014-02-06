import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		sim_dst = self.get_arg_value(1)
		sim_size = self.get_arg_value(2)
		sim_nm = self.get_arg_value(3)
		file_ptr = self.get_arg_value(4)

		plugin = self.state.get_plugin('posix')

		if sim_size.is_symbolic():
			# TODO improve this
			length = sim_size.max_value()
		else:
			length = sim_size.any()

		if sim_nm.is_symbolic():
			# TODO improve this
			length *= sim_nm.max_value()
		else:
			length *= sim_nm.any()

		if length > plugin.max_length:
			length = plugin.max_length

		# TODO handle errors
		data = plugin.read(file_ptr.expr.fd, length)
		self.state.store_mem(sim_dst.expr, data)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, self.state.expr_value(data), length, [], [], [], []))
		self.exit_return(length)
