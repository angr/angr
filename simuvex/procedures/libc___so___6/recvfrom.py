import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		plugin = self.state['posix']

		# TODO: Now it's limiting UDP package to 25 bytes
		# We need to better handling for this
		length = self.state.BVV(40, self.state.arch.bits)

		_ = plugin.pos(fd)
		data = plugin.read(fd, length)
		self.state.store_mem(dst, data)
		self.ret(length)
