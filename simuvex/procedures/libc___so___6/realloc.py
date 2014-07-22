import simuvex

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		plugin = self.state.get_plugin('libc')
		ptr = self.arg(0)
		size = self.arg(1)

		if self.state.symbolic(size):
			# TODO: find a better way
			size = self.state.max(size)
			if size > plugin.max_variable_size:
				size = plugin.max_variable_size
		else:
			size = self.state.any(size)

		addr = plugin.heap_location
		v = self.state.mem_expr(ptr, size)
		self.state.store_mem(addr, v)
		plugin.heap_location += size

		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, addr, v, size, [], [], [], []))
		self.ret(addr)
