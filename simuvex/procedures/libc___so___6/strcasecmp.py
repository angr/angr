import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt

import logging
l = logging.getLogger("simuvex.procedures.strcasecmp")

class strcasecmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		a_addr = self.arg(0)
		b_addr = self.arg(1)

		self.argument_types = { 0: self.ty_ptr(SimTypeString()),
				       			1: self.ty_ptr(SimTypeString())}
		self.return_type = SimTypeInt(32, True)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = strlen(self.state, inline=True, arguments=[a_addr])
		b_strlen = strlen(self.state, inline=True, arguments=[b_addr])
		maxlen = self.state.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

		strncmp = self.inline_call(simuvex.SimProcedures['libc.so.6']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen)
		self.ret(strncmp.ret_expr)
