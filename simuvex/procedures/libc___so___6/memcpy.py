import simuvex
from simuvex.s_type import SimTypeTop, SimTypeLength

import logging
l = logging.getLogger("simuvex.procedures.libc.memcpy")

class memcpy(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		dst_addr = self.arg(0)
		src_addr = self.arg(1)
		limit = self.arg(2)

		# TODO: look into smarter types here
		self.argument_types = {0: self.ty_ptr(SimTypeTop()),
							   1: self.ty_ptr(SimTypeTop()),
							   2: SimTypeLength(self.state.arch)}
		self.return_type = self.ty_ptr(SimTypeTop())

		if not self.state.symbolic(limit):
			conditional_size = self.state.any_int(limit)
		else:
			max_memcpy_size = self.state['libc'].max_buffer_size
			conditional_size = max(self.state.min_int(limit), min(self.state.max_int(limit), max_memcpy_size))

		l.debug("Memcpy running with conditional_size %d", conditional_size)

		if conditional_size > 0:
			src_mem = self.state.mem_expr(src_addr, conditional_size, endness='Iend_BE')
			self.state.store_mem(dst_addr, src_mem, symbolic_length=limit, endness='Iend_BE')

			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, src_addr, src_mem, conditional_size))
			self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst_addr, src_mem, conditional_size))

		self.ret(dst_addr)
