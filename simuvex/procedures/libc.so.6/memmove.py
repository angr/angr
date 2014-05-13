import simuvex

import logging
l = logging.getLogger("simuvex.procedures.libc.memmove")

class memmove(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

		dst_addr = self.get_arg_expr(0)
		src_addr = self.get_arg_expr(1)
		limit = self.get_arg_expr(2)
		self.inline_call(memcpy, dst_addr, src_addr, limit)
		self.exit_return(dst_addr)

