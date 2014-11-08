import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		length = self.arg(2)
		plugin = self.state['posix']

		_ = plugin.pos(fd)

		data = plugin.read(fd, self.state.se.any_int(length))
		self.state.store_mem(dst, data)
		return length
