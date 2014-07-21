import simuvex

import logging
l = logging.getLogger("simuvex.procedures.libc.strncmp")

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
		ret_expr = self.state.BV("strncmp_ret", self.state.arch.bits)

		# determine the maximum number of bytes to compare
		concrete_run = False
		if not a_len.is_symbolic() and not b_len.is_symbolic() and not limit.is_symbolic():
			c_a_len = a_len.any()
			c_b_len = b_len.any()
			c_limit = limit.any()

			l.debug("everything is concrete: a_len %d, b_len %d, limit %d", c_a_len, c_b_len, c_limit)

			if (c_a_len < c_limit or c_b_len < c_limit) and c_a_len != c_b_len:
				l.debug("lengths < limit and unmatched")
				self.exit_return(self.state.claripy.BitVecVal(1, self.state.arch.bits))
				self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(a_addr), self.state.mem_expr(a_addr, c_a_len + 1), c_a_len + 1))
				self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(b_addr), self.state.mem_expr(b_addr, c_b_len + 1), c_b_len + 1))
				return

			concrete_run = True
			maxlen = min(c_a_len, c_b_len, c_limit)
		else:
			if not limit.is_symbolic():
				c_limit = limit.any()
				maxlen = min(a_strlen.max_null_index, b_strlen.max_null_index, c_limit)
			else:
				maxlen = max(a_strlen.max_null_index, b_strlen.max_null_index)

			match_constraints.append(self.state.claripy.Or(a_len.expr == b_len.expr, self.state.claripy.And(self.state.claripy.UGE(a_len.expr, limit.expr), self.state.claripy.UGE(b_len.expr, limit.expr))))

		if maxlen == 0:
			l.debug("returning equal for 0-length maximum strings")
			self.exit_return(self.state.claripy.BitVecVal(0, self.state.arch.bits))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(a_addr), self.state.mem_expr(a_addr, 1), 1))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(b_addr), self.state.mem_expr(b_addr, 1), 1))
			return

		# wtf, z3
		maxlen = int(maxlen)

		# the bytes
		a_bytes = self.state.mem_expr(a_addr, maxlen, endness='Iend_BE')
		b_bytes = self.state.mem_expr(b_addr, maxlen, endness='Iend_BE')

		# TODO: deps
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(a_addr), self.state.expr_value(a_bytes), maxlen))
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(b_addr), self.state.expr_value(b_bytes), maxlen))
		for i in range(maxlen):
			l.debug("Processing byte %d", i)
			maxbit = (maxlen-i)*8
			a_byte = a_bytes[maxbit-1, maxbit-8]
			b_byte = b_bytes[maxbit-1, maxbit-8]

			if concrete_run and not a_byte.symbolic and not b_byte.symbolic:
				a_conc = a_byte.eval()
				b_conc = b_byte.eval()
				if a_conc != b_conc:
					l.debug("... found mis-matching concrete bytes 0x%x and 0x%x", a_conc, b_conc)
					self.exit_return(self.state.claripy.BitVecVal(1, self.state.arch.bits))
					return
			else:
				concrete_run = False

			byte_constraint = self.state.claripy.Or(a_byte == b_byte, self.state.claripy.ULT(a_len.expr, i), self.state.claripy.ULT(limit.expr, i))
			match_constraints.append(byte_constraint)

		if concrete_run:
			l.debug("concrete run made it to the end!")
			self.exit_return(self.state.claripy.BitVecVal(0, self.state.arch.bits))
			return

		# make the constraints
		l.debug("returning symbolic")
		match_constraint = self.state.claripy.And(*match_constraints)
		nomatch_constraint = self.state.claripy.Not(match_constraint)

		#l.debug("match constraints: %s", match_constraint)
		#l.debug("nomatch constraints: %s", nomatch_constraint)

		match_case = self.state.claripy.And(limit.expr != 0, match_constraint, ret_expr == 0)
		nomatch_case = self.state.claripy.And(limit.expr != 0, nomatch_constraint, ret_expr == 1)
		l0_case = self.state.claripy.And(limit.expr == 0, ret_expr == 0)
		empty_case = self.state.claripy.And(a_strlen.ret_expr == 0, b_strlen.ret_expr == 0, ret_expr == 0)

		self.state.add_constraints(self.state.claripy.Or(match_case, nomatch_case, l0_case, empty_case))
		self.exit_return(ret_expr)
