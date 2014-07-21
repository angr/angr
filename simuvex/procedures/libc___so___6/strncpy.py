import simuvex
from simuvex.s_helpers import sim_ite_autoadd

import logging
l = logging.getLogger("simuvex.procedures.libc.strcpy")

class strncpy(simuvex.SimProcedure):
	def __init__(self, src_len = None): # pylint: disable=W0231,
		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']

		dst_addr = self.get_arg_expr(0)
		src_addr = self.get_arg_expr(1)
		src_len = src_len if src_len is not None else self.inline_call(strlen, src_addr)
		limit = self.get_arg_value(2)

		cpy_size = sim_ite_autoadd(self.state, self.state.claripy.ULE(limit.expr, src_len.ret_expr + 1), limit.expr, src_len.ret_expr + 1, sym_size=self.state.arch.bits)

		#print "==================="
		#print sorted(self.state.expr_value(src_len.ret_expr).any_n(20))
		#print self.state.expr_value(limit.expr).any_n(20)
		#print sorted(self.state.expr_value(cpy_size).any_n(20))
		#print "-------------------"

		self.inline_call(memcpy, dst_addr, src_addr, cpy_size)
		self.exit_return(dst_addr)

