import simuvex
import symexec as se
import itertools

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

strncmp_counter = itertools.count()

class strncmp(simuvex.SimProcedure):
	def __init__(self, a_len=None, b_len=None): # pylint: disable=W0231,
		a_addr = self.get_arg_expr(0)
		b_addr = self.get_arg_expr(1)
		limit = self.get_arg_value(2)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = a_len if a_len is not None else strlen(self.state, inline=True, arguments=[a_addr])
		b_strlen = b_len if b_len is not None else strlen(self.state, inline=True, arguments=[b_addr])

		a_len = self.state.expr_value(a_strlen.ret_expr)
		b_len = self.state.expr_value(b_strlen.ret_expr)

		match_constraints = [ ]
		ret_expr = se.BitVec("strncmp_ret_%d" % strncmp_counter.next(), self.state.arch.bits)

		# determine the maximum number of bytes to compare
		concrete_lengths = False
		if not a_len.is_symbolic() and not b_len.is_symbolic() and not limit.is_symbolic():
			c_a_len = a_len.any()
			c_b_len = b_len.any()
			c_limit = limit.any()

			if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
				self.exit_return(se.BitVecVal(1, self.state.arch.bits))
				return

			concrete_lengths = True
			maxlen = min(c_a_len, c_b_len, c_limit)
		else:
			if not limit.is_symbolic():
				c_limit = limit.any()
				maxlen = min(a_strlen.maximum_null, b_strlen.maximum_null, c_limit)
			else:
				maxlen = min(a_strlen.maximum_null, b_strlen.maximum_null)

			match_constraints.append(se.Or(a_len.expr == b_len.expr, se.And(a_len.expr >= limit.expr, b_len.expr >= limit.expr)))

		# the bytes
		a_bytes = self.state.mem_expr(a_addr, maxlen, endness='Iend_BE')
		b_bytes = self.state.mem_expr(b_addr, maxlen, endness='Iend_BE')
		for i in range(maxlen):
			l.debug("Processing byte %d", i)
			maxbit = (maxlen-i)*8
			a_byte = se.Extract(maxbit-1, maxbit-8, a_bytes)
			b_byte = se.Extract(maxbit-1, maxbit-8, b_bytes)

			if concrete_lengths and not se.is_symbolic(a_byte) and not se.is_symbolic(b_byte):
				if se.concretize_constant(a_byte) != se.concretize_constant(b_byte):
					l.debug("... found mis-matching concrete bytes!")
					self.exit_return(se.BitVecVal(1, self.state.arch.bits))
					return

			byte_constraint = se.Or(a_byte == b_byte, se.ULT(a_len.expr, i), se.ULT(limit.expr, i))
			match_constraints.append(byte_constraint)

		# make the constraints
		match_constraint = se.And(*match_constraints)
		nomatch_constraint = se.Not(match_constraint)

		#l.debug("match constraints: %s", match_constraint)
		#l.debug("nomatch constraints: %s", nomatch_constraint)

		self.state.add_constraints(se.Or(se.And(match_constraint, ret_expr == 0), se.And(nomatch_constraint, ret_expr == 1)))
		self.exit_return(ret_expr)
