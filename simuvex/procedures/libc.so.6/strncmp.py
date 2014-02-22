import simuvex
import symexec as se
import itertools

import logging
l = logging.getLogger("simuvex.procedures.libc.strncmp")

strncmp_counter = itertools.count()

class strncmp(simuvex.SimProcedure):
	def __init__(self, a_len=None, b_len=None): # pylint: disable=W0231,
		a_addr = self.get_arg_expr(0)
		b_addr = self.get_arg_expr(1)
		limit = self.get_arg_value(2)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		a_strlen = a_len if a_len is not None else self.inline_call(strlen, a_addr)
		b_strlen = b_len if b_len is not None else self.inline_call(strlen, b_addr)

		a_len = self.state.expr_value(a_strlen.ret_expr)
		b_len = self.state.expr_value(b_strlen.ret_expr)

		match_constraints = [ ]
		ret_expr = se.BitVec("strncmp_ret_%d" % strncmp_counter.next(), self.state.arch.bits)

		# determine the maximum number of bytes to compare
		concrete_run = False
		if not a_len.is_symbolic() and not b_len.is_symbolic() and not limit.is_symbolic():
			c_a_len = a_len.any()
			c_b_len = b_len.any()
			c_limit = limit.any()

			l.debug("everything is concrete: a_len %d, b_len %d, limit %d", c_a_len, c_b_len, c_limit)

			if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
				l.debug("lengths < limit and unmatched")
				self.exit_return(se.BitVecVal(1, self.state.arch.bits))
				return

			concrete_run = True
			maxlen = min(c_a_len, c_b_len, c_limit)
		else:
			if not limit.is_symbolic():
				c_limit = limit.any()
				maxlen = min(a_strlen.maximum_null, b_strlen.maximum_null, c_limit)
			else:
				maxlen = min(a_strlen.maximum_null, b_strlen.maximum_null)

			match_constraints.append(se.Or(a_len.expr == b_len.expr, se.And(se.UGE(a_len.expr, limit.expr), se.UGE(b_len.expr, limit.expr))))

		# the bytes
		a_bytes = self.state.mem_expr(a_addr, maxlen, endness='Iend_BE')
		b_bytes = self.state.mem_expr(b_addr, maxlen, endness='Iend_BE')

		# TODO: deps
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(a_addr), self.state.expr_value(a_bytes), maxlen))
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(b_addr), self.state.expr_value(b_bytes), maxlen))
		for i in range(maxlen):
			l.debug("Processing byte %d", i)
			maxbit = (maxlen-i)*8
			a_byte = se.Extract(maxbit-1, maxbit-8, a_bytes)
			b_byte = se.Extract(maxbit-1, maxbit-8, b_bytes)

			if concrete_run and not se.is_symbolic(a_byte) and not se.is_symbolic(b_byte):
				a_conc = se.concretize_constant(a_byte)
				b_conc = se.concretize_constant(b_byte)
				if a_conc != b_conc:
					l.debug("... found mis-matching concrete bytes 0x%x and 0x%x", a_conc, b_conc)
					self.exit_return(se.BitVecVal(1, self.state.arch.bits))
					return
			else:
				concrete_run = False

			byte_constraint = se.Or(a_byte == b_byte, se.ULT(a_len.expr, i), se.ULT(limit.expr, i))
			match_constraints.append(byte_constraint)

		if concrete_run:
			l.debug("concrete run made it to the end!")
			self.exit_return(se.BitVecVal(0, self.state.arch.bits))
			return

		# make the constraints
		l.debug("returning symbolic")
		match_constraint = se.And(*match_constraints)
		nomatch_constraint = se.Not(match_constraint)

		#l.debug("match constraints: %s", match_constraint)
		#l.debug("nomatch constraints: %s", nomatch_constraint)

		match_case = se.And(limit.expr != 0, match_constraint, ret_expr == 0)
		nomatch_case = se.And(limit.expr != 0, nomatch_constraint, ret_expr == 1)
		l0_case = se.And(limit.expr == 0, ret_expr == 0)
		empty_case = se.And(a_strlen.ret_expr == 0, b_strlen.ret_expr == 0, ret_expr == 0)

		self.state.add_constraints(se.Or(match_case, nomatch_case, l0_case, empty_case))
		self.exit_return(ret_expr)
