import simuvex

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class strlen(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		s = self.arg(0)

		max_symbolic = self.state['libc'].buf_symbolic_bytes
		max_str_len = self.state['libc'].max_str_len

		r, c, i = self.state.memory.find(s, self.state.BVV(0, 8), max_str_len, max_symbolic=max_symbolic)

		self.max_null_index = max(i)
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, s, 0, self.max_null_index+1))
		self.state.add_constraints(*c)
		self.ret(r - s)
