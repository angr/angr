import simuvex
from simuvex.s_type import SimTypeLength, SimTypeTop

import logging
l = logging.getLogger("simuvex.procedures.libc.realloc")

######################################
# realloc
######################################

class realloc(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		plugin = self.state.get_plugin('libc')
		ptr = self.arg(0)
		size = self.arg(1)

		size_int = min(self.state.se.max_int(size), plugin.max_variable_size)
		l.debug("Size: %d", size_int)
		self.state.add_constraints(size_int == size)

		self.argument_types = { 0: self.ty_ptr(SimTypeTop()),
				       			1: SimTypeLength(self.state.arch)}
		self.return_type = self.ty_ptr(SimTypeTop(size))

		addr = plugin.heap_location
		v = self.state.mem_expr(ptr, size_int)
		self.state.store_mem(addr, v)
		plugin.heap_location += size_int

		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.BVV(addr, self.state.arch.bits), v, size, [], [], [], []))
		self.ret(addr)
