import simuvex

######################################
# recvfrom
######################################

class recvfrom(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		plugin = self.state['posix']

		# TODO: Now it's limiting UDP package to 25 bytes
		# We need to better handling for this
		length = self.state.BVV(40, self.state.arch.bits)

		# TODO handle errors
		data = plugin.read(fd.expr, length)
		self.state.store_mem(dst.expr, data)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, length, [], [], [], []))
		self.ret(length)
