import simuvex
from simuvex.s_type import SimTypePointer, SimTypeTop, SimTypeInt, SimTypeLength
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.memset")

######################################
# memset
######################################

import itertools
memset_counter = itertools.count()

class memset(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
                self.argument_types = {0: self.ty_ptr(SimTypeTop()),
                                       1: SimTypeInt(32, True), # ?
                                       2: SimTypeLength(self.state.arch)}
                self.return_type = self.ty_ptr(SimTypeTop())

		dst_addr = self.get_arg_expr(0)
		char = se.Extract(7, 0, self.get_arg_expr(1))
		num = self.get_arg_value(2)

		if num.is_symbolic():
			max_size = num.min() + self.state['libc'].max_buffer_size
			write_bytes = se.Concat(*([ char ] * max_size))
			self.state.store_mem(dst_addr, write_bytes, symbolic_length=num)
		else:
			max_size = num.any()
			write_bytes = se.Concat(*([ char ] * max_size))
			self.state.store_mem(dst_addr, write_bytes)

			l.debug("memset writing %d bytes", max_size)

		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, self.state.expr_value(dst_addr), write_bytes, max_size*8, [], [], [], []))
		self.exit_return(dst_addr)
