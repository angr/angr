import simuvex
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.libc.strstr")

class strstr(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		haystack_addr = self.get_arg_expr(0)
		needle_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		strncmp = simuvex.SimProcedures['libc.so.6']['strncmp']

		haystack_strlen = self.inline_call(strlen, haystack_addr)
		needle_strlen = self.inline_call(strlen, needle_addr)

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

		cases = [ [ needle_strlen.ret_expr == 0, haystack_addr ] ]
		exclusions = [ needle_strlen.ret_expr != 0 ]
		for i in range(haystack_maxlen):
			l.debug("... case %d", i)

			# big hack!
			cmp_res = self.inline_call(strncmp, haystack_addr + i, needle_addr, needle_strlen.ret_expr, a_len=haystack_strlen, b_len=needle_strlen)
			c = se.And(*([ se.UGE(haystack_strlen.ret_expr, needle_strlen.ret_expr), cmp_res.ret_expr == 0 ] + exclusions))
			exclusions.append(cmp_res.ret_expr != 0)

			#print "CASE:", c
			cases.append([ c, haystack_addr + i ])
			haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1
		cases.append([ se.And(*exclusions), 0 ])
		r, c = simuvex.helpers.sim_cases(self.state, cases, sym_name="strstr", sym_size=self.state.arch.bits)
		self.state.add_constraints(*c)
		self.exit_return(r)
