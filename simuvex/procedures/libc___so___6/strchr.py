import simuvex

import logging
l = logging.getLogger("simuvex.procedures.libc.strchr")

class strchr(simuvex.SimProcedure):
	def __init__(self, s_strlen=None): # pylint: disable=W0231,
		s_addr = self.arg(0)
		c = self.arg(1)[7:0]

		s_strlen = self.inline_call(simuvex.SimProcedures['libc.so.6']['strlen'], s_addr)

		if self.state.symbolic(s_strlen.ret_expr):
			l.debug("symbolic strlen")
			# TODO: more constraints here to make sure we don't search too little
			max_sym = min(self.state.max(s_strlen.ret_expr), self.state['libc'].max_symbolic_strchr)
			a, c, i = self.state.memory.find(s_addr, c, s_strlen.max_null_index, max_symbolic=max_sym, default=0)
		else:
			l.debug("symbolic strlen")
			max_search = self.state.any(s_strlen.ret_expr)
			a, c, i = self.state.memory.find(s_addr, c, max_search, default=0)

		self.symbolic_return = True
		self.state.add_constraints(*c)
		self.state.add_constraints(a - s_addr < s_strlen.ret_expr)
		self.max_chr_index = max(i)
		self.ret(a)
