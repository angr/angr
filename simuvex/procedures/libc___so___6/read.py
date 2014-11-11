import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################

class read(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def run(self, fd, dst, length):
		self.argument_types = {0: SimTypeFd(),
							   1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
							   2: SimTypeLength(self.state.arch)}
		self.return_type = SimTypeLength(self.state.arch)

		if self.state.se.max_int(length) == 0:
			return self.state.se.BVV(0, self.state.arch.bits)

		# TODO handle errors
		_ = self.state.posix.pos(fd)
		data = self.state.posix.read(fd, length)
		self.state.store_mem(dst, data)
		return length
