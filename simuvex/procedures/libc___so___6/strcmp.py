import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

class strcmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
                self.argument_types = {0: self.ty_ptr(SimTypeString()),
                                       1: self.ty_ptr(SimTypeString())}
                self.return_type = SimTypeInt(32, True)

		a_addr = self.get_arg_expr(0)
		b_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = strlen(self.state, inline=True, arguments=[a_addr])
		b_strlen = strlen(self.state, inline=True, arguments=[b_addr])
		maxlen = se.BitVecVal(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

		strncmp = self.inline_call(simuvex.SimProcedures['libc.so.6']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen)
		self.exit_return(strncmp.ret_expr)
