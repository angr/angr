import simuvex
import symexec

import logging
l = logging.getLogger("simuvex.procedures.libc.strlen")

class strlen(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		s = self.get_arg_expr(0)

		len_expr = self.state.new_symbolic("strlen_len", self.state.arch.bits)
		len_parts = [ ]

		remaining_symbolic = self.state['libc'].max_str_symbolic_bytes
		first_symbolic = None

		i = -1
		while True:
			l.debug("remaining symbolic bytes: %s", remaining_symbolic)
			i += 1

			# TODO: maybe read this all at once so that we
			#don't have multiple address concretization

			b = self.state.mem_expr(s + i, 1, endness="Iend_BE")
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(s+i), self.state.expr_value(b), 1))
			if not symexec.is_symbolic(b):
				c = symexec.concretize_constant(b)
				if c == 0:
					l.debug("found the 0 at location %d!", i)
					len_parts.append(symexec.ULE(len_expr, i))
					break
				else:
					l.debug("skipping concrete byte 0x%x", c)
					continue
			else:
				if first_symbolic is None: first_symbolic = i
				l.debug("appending symbolic condition for length %s", i)

				#
				# three options:
				#
				byte_constraints = [ ]

				# 0. b == 0, length == i
				byte_constraints.append(symexec.And(b == 0, len_expr == i))
				#print "0:", byte_constraints[0]
				# 1. b != 0, length >= i
				byte_constraints.append(symexec.And(b != 0, symexec.UGT(len_expr, i)))
				#print "1:", byte_constraints[1]
				# 2. length < i
				if i > 0:
					byte_constraints.append(symexec.ULT(len_expr, i))
					#print "2:", byte_constraints[2]

				byte_constraint = symexec.Or(*byte_constraints)
				len_parts.append(byte_constraint)

				remaining_symbolic -= 1
				if not remaining_symbolic:
					l.debug("out of symbolic bytes. Aborting!")
					break

		self.maximum_null = i
		l.debug("maximum length (index of null): %s", self.maximum_null)

		if first_symbolic is not None:
			l.debug("returning symbolic length")

			self.state.add_constraints(symexec.ULE(len_expr, self.maximum_null))
			self.state.add_constraints(symexec.UGE(len_expr, first_symbolic))
			self.state.add_constraints(symexec.And(*len_parts))
		else:
			l.debug("returning concrete length %d", i)
			len_expr = symexec.BitVecVal(i, self.state.arch.bits)

		self.exit_return(len_expr)
