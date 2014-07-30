import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		length = self.arg(2)
		plugin = self.state['posix']

		# TODO handle errors
		data = plugin.read(fd, length)
		self.state.store_mem(dst, data)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, length))
		self.ret(length)
