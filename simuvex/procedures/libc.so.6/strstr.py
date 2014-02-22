import simuvex
import symexec as se
import itertools

import logging
l = logging.getLogger("simuvex.procedures.strstr")

strstr_counter = itertools.count()

class strstr(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		haystack_addr = self.get_arg_expr(0)
		needle_addr = self.get_arg_expr(1)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		strncmp = simuvex.SimProcedures['libc.so.6']['strncmp']

		haystack_strlen = self.inline_call(strlen, haystack_addr)
		needle_strlen = self.inline_call(strlen, needle_addr)

		# naive approach
		haystack_maxlen = haystack_strlen.maximum_null
		needle_maxlen = needle_strlen.maximum_null

		l.debug("Maxlen: %d, %d", haystack_maxlen, needle_maxlen)
		#l.debug("addrs: %s, %s", haystack_addr, needle_addr)

		ret_expr = se.BitVec("strstr_ret_%d" % strstr_counter.next(), self.state.arch.bits)

		if needle_maxlen == 0:
			l.debug("zero-length needle.")
			self.exit_return(haystack_addr)
			return

		# initialize the bytes after haystack, just in case
		# (for later consistency when searching for needle at the end of haystack)
		self.state.mem_expr(haystack_addr + haystack_maxlen, needle_maxlen)

		#self.state.add_constraints(se.UGT(needle_strlen.ret_expr, 0))
		#self.state.add_constraints(se.UGT(haystack_strlen.ret_expr, 0))

		return_possibilities = [ ]
		cmp_rets = [ ]

		#definite_match = False
		orig_haystack_len = haystack_strlen.ret_expr
		any_symbolic = False

		for i in range(haystack_maxlen):
			c = self.inline_call(strncmp, haystack_addr + i, needle_addr, needle_strlen.ret_expr, a_len=haystack_strlen, b_len=needle_strlen)
			#print "NEW:", se.simplify_expression(se.And(i_state.new_constraints))

			if not se.is_symbolic(c.ret_expr) and se.concretize_constant(c.ret_expr) == 0:
				l.debug("found it concretely! Setting definite_match")
				#definite_match = True

				if not any_symbolic:
					l.debug("first match is a concrete one. Returning concrete.")
					self.exit_return(haystack_addr + i)
					return

			any_symbolic = True
			return_possibilities.append(se.And(c.ret_expr == 0, ret_expr == haystack_addr + i, se.BoolVal(True) if len(cmp_rets) == 0 else se.And(*[ _ != 0 for _ in cmp_rets ])))

			# tail
			haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1
			cmp_rets.append(c.ret_expr)

		l.debug("Returning normally")
		nomatch = se.And(*[ c != 0 for c in cmp_rets ])
		match = se.Or(*[ c == 0 for c in cmp_rets ])

		n0 = needle_strlen.ret_expr == 0
		nX = needle_strlen.ret_expr != 0
		h0 = orig_haystack_len == 0
		hX = orig_haystack_len != 0

		noeither_case = se.And(n0, h0, ret_expr == haystack_addr)
		noneedle_case = se.And(n0, hX, ret_expr == haystack_addr)
		nohaystack_case = se.And(nX, h0, ret_expr == 0)
		nomatch_case = se.And(nX, hX, nomatch, ret_expr == 0)
		match_case   = se.And(nX, hX, match, se.Or(*return_possibilities))

		self.state.add_constraints(se.Or(nomatch_case, noneedle_case, nohaystack_case, noeither_case, match_case))
		self.exit_return(ret_expr)
