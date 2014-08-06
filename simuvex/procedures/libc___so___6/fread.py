import simuvex

######################################
# fread
######################################

class fread(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		# TODO: Symbolic fd
		dst = self.arg(1)
		size = self.arg(2)
		nm = self.arg(3)
		file_ptr = self.arg(4)

		plugin = self.state.get_plugin('posix')

		# TODO handle errors
		old_pos = plugin.pos(file_ptr)
		data = plugin.read(file_ptr, size * nm)
		self.state.store_mem(dst, data)
		self.add_refs(simuvex.SimFileRead(self.addr, self.stmt_from, file_ptr, old_pos, data, size*nm))
		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, size))
		self.ret(size) #TODO: handle reading less than nm items somewhere
