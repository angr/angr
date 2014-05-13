import simuvex
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class strlen(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		s = self.get_arg_expr(0)

		max_symbolic = self.state['libc'].max_str_symbolic_bytes
		r, c, i = self.state.memory.find(s, se.BitVecVal(0, 8), max_symbolic=max_symbolic)
		self.max_null_index = max(i)
		self.state.add_constraints(*c)
		self.exit_return(r - s)
