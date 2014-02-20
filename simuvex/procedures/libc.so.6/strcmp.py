import simuvex
import symexec as se
import itertools

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

strcmp_counter = itertools.count()

class strcmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		a_addr = self.get_arg_expr(0)
		b_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = strlen(self.state, inline=True, arguments=[a_addr])
		b_strlen = strlen(self.state, inline=True, arguments=[b_addr])
		maxlen = se.BitVecVal(max(a_strlen.maximum_null, b_strlen.maximum_null), self.state.arch.bits)

		strncmp = simuvex.SimProcedures['libc.so.6']['strncmp'](self.state, inline=True, arguments=[a_addr, b_addr, maxlen], a_len=a_strlen, b_len=b_strlen)
		self.exit_return(strncmp.ret_expr)
