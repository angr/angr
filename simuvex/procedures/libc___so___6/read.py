import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################

class read(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		length = self.arg(2)

		self.argument_types = {0: SimTypeFd(),
							   1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
							   2: SimTypeLength(self.state.arch)}
		self.return_type = SimTypeLength(self.state.arch)
		plugin = self.state['posix']

		if self.state.se.max_int(length) == 0:
			return self.state.se.BVV(0, self.state.arch.bits)

		# TODO handle errors
		_ = plugin.pos(fd)
		data = plugin.read(fd, length)
		self.state.store_mem(dst, data)
		return length
