import simuvex
from simuvex.s_type import SimTypeString, SimType
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.libc.strstr")

class strstr(simuvex.SimProcedure):
	def __init__(self, haystack_strlen=None, needle_strlen=None): # pylint: disable=W0231,
                self.argument_types = {0: self.ty_ptr(SimTypeString()),
                                       1: self.ty_ptr(SimTypeString())}
                self.return_type = self.ty_ptr(SimTypeString())

		haystack_addr = self.get_arg_expr(0)
		needle_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		strncmp = simuvex.SimProcedures['libc.so.6']['strncmp']

		haystack_strlen = self.inline_call(strlen, haystack_addr) if haystack_strlen is None else haystack_strlen
		needle_strlen = self.inline_call(strlen, needle_addr) if needle_strlen is None else needle_strlen

		# naive approach
		haystack_maxlen = haystack_strlen.max_null_index
		needle_maxlen = needle_strlen.max_null_index

		l.debug("strstr with size %d haystack and size %d needle...", haystack_maxlen, needle_maxlen)

		if needle_maxlen == 0:
			l.debug("... zero-length needle.")
			self.exit_return(haystack_addr)
			return
		elif haystack_maxlen == 0:
			l.debug("... zero-length haystack.")
			self.exit_return(se.BitVecVal(0, self.state.arch.bits))
			return

		if se.is_symbolic(needle_strlen.ret_expr):
			cases = [ [ needle_strlen.ret_expr == 0, haystack_addr ] ]
			exclusions = [ needle_strlen.ret_expr != 0 ]
			remaining_symbolic = self.state['libc'].max_symbolic_strstr
			for i in range(haystack_maxlen):
				l.debug("... case %d (%d symbolic checks remaining)", i, remaining_symbolic)

				# big hack!
				cmp_res = self.inline_call(strncmp, haystack_addr + i, needle_addr, needle_strlen.ret_expr, a_len=haystack_strlen, b_len=needle_strlen)
				c = se.And(*([ se.UGE(haystack_strlen.ret_expr, needle_strlen.ret_expr), cmp_res.ret_expr == 0 ] + exclusions))
				exclusions.append(cmp_res.ret_expr != 0)

				if se.is_symbolic(c):
					remaining_symbolic -= 1

				#print "CASE:", c
				cases.append([ c, haystack_addr + i ])
				haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1

				if remaining_symbolic == 0:
					l.debug("... exhausted remaining symbolic checks.")
					break

			cases.append([ se.And(*exclusions), 0 ])
			l.debug("... created %d cases", len(cases))
			r, c = simuvex.helpers.sim_cases(self.state, cases, sym_name="strstr", sym_size=self.state.arch.bits)
		else:
			needle_length = se.concretize_constant(needle_strlen.ret_expr)
			needle_str = self.state.mem_expr(needle_addr, needle_length)

			r, c, i = self.state.memory.find(haystack_addr, needle_str, haystack_strlen.max_null_index, max_symbolic=self.state['libc'].max_symbolic_strstr, default=0)

			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(needle_addr), needle_str, needle_length*8))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(haystack_addr), self.state.expr_value(0), haystack_strlen.max_null_index*8))

		self.state.add_constraints(*c)
		self.exit_return(r)
