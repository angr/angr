import simuvex
from simuvex.s_type import SimTypeFd, SimTypeChar, SimTypeArray, SimTypeLength

######################################
# fgets
######################################

class fgets(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Symbolic fd
		dst = self.arg(0)
		size = self.arg(1)
		fd = self.arg(2)

		self.argument_types = {2: SimTypeFd(),
							   0: self.ty_ptr(SimTypeArray(SimTypeChar(), size)),
							   1: SimTypeLength(self.state.arch)}
		self.return_type = self.argument_types[0]
		plugin = self.state['posix']

		f = plugin.get_file(fd)
		old_pos = plugin.pos(fd)

		_,constraints = self.state.memory.copy_contents(dst, old_pos, size, src_memory=f.content)
		self.state.add_constraints(*constraints)

		self.ret(dst)
