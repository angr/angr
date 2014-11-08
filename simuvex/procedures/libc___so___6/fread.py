import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Symbolic fd
		dst = self.arg(1)
		size = self.arg(2)
		nm = self.arg(3)
		file_ptr = self.arg(4)

		plugin = self.state.get_plugin('posix')

		# TODO handle errors
		_ = plugin.pos(file_ptr)
		data = plugin.read(file_ptr, size * nm)
		self.state.store_mem(dst, data)
		return size #TODO: handle reading less than nm items somewhere
