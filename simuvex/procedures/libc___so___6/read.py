import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# read
######################################

class read(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		fd = self.arg(0)
		dst = self.arg(1)
		length = self.arg(2)

		self.argument_types = {0: SimTypeFd(),
							   1: self.ty_ptr(SimTypeArray(SimTypeChar(), length)),
							   2: SimTypeLength(self.state.arch)}
		self.return_type = SimTypeLength(self.state.arch)
		plugin = self.state['posix']

		# TODO handle errors
		data = plugin.read(fd, length)
		self.state.store_mem(dst, data)
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, length, [], [], [], []))
		self.ret(length)
