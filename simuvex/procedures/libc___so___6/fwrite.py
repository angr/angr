import simuvex

######################################
# fwrite
######################################

class fwrite(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		# TODO: Symbolic fd
		plugin = self.state.get_plugin('posix')
		src = self.arg(0)
		size = self.arg(1)
		nmemb = self.arg(2)
		file_ptr = self.arg(3)

		# TODO handle errors
		data = self.state.mem_expr(src, size, "Iend_BE")
		written = plugin.write(file_ptr, data, size*nmemb)

		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, src, data, written, (), ()))
		self.ret(written)
