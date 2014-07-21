import simuvex

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

class strcmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		a_addr = self.get_arg_expr(0)
		b_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = strlen(self.state, inline=True, arguments=[a_addr])
		b_strlen = strlen(self.state, inline=True, arguments=[b_addr])
		maxlen = self.state.claripy.BitVecVal(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

		strncmp = self.inline_call(simuvex.SimProcedures['libc.so.6']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen)
		self.exit_return(strncmp.ret_expr)
