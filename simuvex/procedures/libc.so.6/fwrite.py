import simuvex
import symexec

######################################
# fwrite
######################################

class fwrite(simuvex.SimProcedure):
	def __init__(self, ret_expr):
		# TODO: Symbolic fd
		plugin = self.state.get_plugin('posix')
		sim_src = self.get_arg_value(0)
		sim_size = self.get_arg_value(1)
		sim_nmemb = self.get_arg_value(2)
		file_ptr = self.get_arg_value(3)

		if sim_size.is_symbolic():
			# TODO improve this
			length = sim_size.max_value()
		else:
			length = sim_size.any()

		if sim_nmemb.is_symbolic():
			# TODO improve this
			length *= sim_nmemb.max_value()
		else:
			length *= sim_nmemb.any()


		if length > plugin.max_length:
			length = plugin.max_length

		# TODO handle errors
		data = self.state.mem_expr(sim_src, length)
		length = plugin.write(file_ptr.fd, data, length)

		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src,
						 data, length, (), ()))


		self.set_return_expr(length)
		self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
