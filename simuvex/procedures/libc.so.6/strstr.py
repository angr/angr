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

		haystack_strlen = strlen(self.state, inline=True, arguments=[haystack_addr])
		needle_strlen = strlen(self.state, inline=True, arguments=[needle_addr])

		haystack_lenval = self.state.expr_value(haystack_strlen.ret_expr)
		needle_lenval = self.state.expr_value(needle_strlen.ret_expr)

		# naive approach
		haystack_maxlen = haystack_lenval.max()
		needle_maxlen = needle_lenval.max()

		l.debug("Maxlen: %d, %d", haystack_maxlen, needle_maxlen)
		l.debug("addrs: %s, %s", haystack_addr, needle_addr)

		ret_expr = se.BitVec("strstr_ret_%d" % strstr_counter.next(), self.state.arch.bits)

		# initialize the bytes after haystack, just in case
		# (for later consistency when searching for needle at the end of haystack)
		self.state.mem_expr(haystack_addr + haystack_maxlen, needle_maxlen)

		return_possibilities = [ ]
		definite_match = False
		#original_haystack_strlen = haystack_strlen.ret_expr
		any_symbolic = False

		for i in range(haystack_maxlen):
			i_state = self.state.copy_after()

			c = strncmp(i_state, inline=True, arguments=[haystack_addr + i, needle_addr, needle_strlen.ret_expr], a_len=haystack_strlen, b_len=needle_strlen)
			print "NEW:", se.simplify_expression(se.And(i_state.new_constraints))

			i_constraints = [ ]
			if not se.is_symbolic(c.ret_expr) and se.concretize_constant(c.ret_expr) == 0:
				l.debug("found it concretely! Setting definite_match")
				definite_match = True

				if not any_symbolic:
					l.debug("first match is a concrete one. Returning concrete.")
					self.exit_return(haystack_addr + i)
					return

			i_constraints.extend(i_state.new_constraints)
			i_constraints.append(ret_expr == haystack_addr + i)
			i_constraints.append(se.UGE(haystack_strlen.ret_expr, 0))
			i_constraints.append(c.ret_expr == 0)
			#if len(return_possibilities) > 0:
			#	i_constraints.append(se.Not(se.Or(*return_possibilities)))

			return_possibilities.append(se.And(*i_constraints))
			haystack_strlen.ret_expr = haystack_strlen.ret_expr - 1

		nomatch_constraints = [ ret_expr == 0, se.Not(se.Or(*return_possibilities)), se.BoolVal(not definite_match) ]
		return_possibilities.append(se.And(*nomatch_constraints))

		self.state.add_constraints(se.Or(*return_possibilities))
		self.exit_return(ret_expr)
