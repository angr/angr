import simuvex
from simuvex.s_type import SimTypeString, SimTypeInt, SimTypeChar
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.libc.strchr")

class strchr(simuvex.SimProcedure):
	def __init__(self, s_strlen=None): # pylint: disable=W0231,
                self.argument_types = {0: self.ty_ptr(SimTypeString()),
                                       1: SimTypeInt(32, True)} # ?
                self.return_type = self.ty_ptr(SimTypeChar()) # ?

		s_addr = self.get_arg_expr(0)
		c = se.Extract(7, 0, self.get_arg_expr(1))

		s_strlen = self.inline_call(simuvex.SimProcedures['libc.so.6']['strlen'], s_addr)

		if self.state.expr_value(s_strlen.ret_expr).is_symbolic():
			max_sym = self.state['libc'].max_symbolic_strchr
			a, c, i = self.state.memory.find(s_addr, c, s_strlen.max_null_index, max_symbolic=max_sym, default=0)
		else:
			max_search = self.state.expr_value(s_strlen.ret_expr).any()
			a, c, i = self.state.memory.find(s_addr, c, max_search, default=0)

		self.symbolic_return = True
		self.state.add_constraints(*c)
		self.state.add_constraints(a - s_addr < s_strlen.ret_expr)
		self.max_chr_index = max(i)
		self.exit_return(a)

