import simuvex
import symexec
import itertools

import logging
l = logging.getLogger("simuvex.procedures.strlen")

strlen_counter = itertools.count()

class strlen(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		s = self.get_arg_expr(0)

		len_expr = symexec.BitVec("strlen_len_%d" % strlen_counter.next(), self.state.arch.bits)
		len_parts = [ ]

		# TODO: can probably go more than max_str_size as long as we're skipping concrete bytes
		remaining_symbolic = self.state['libc'].max_str_size
		first_symbolic = None

		i = 0
		while remaining_symbolic > 0:
			l.debug("remaining symbolic bytes: %d", remaining_symbolic)
			# TODO: maybe read this all at once so that we don't have multiple address concretization
			b = self.state.mem_expr(s + i, 1)
			if not symexec.is_symbolic(b):
				c = symexec.concretize_constant(b)
				if c == 0:
					l.debug("found the 0!")
					len_parts.append(symexec.ULE(len_expr, i))
					break
				else:
					l.debug("skipping concrete byte 0x%x", c)
					i += 1
					continue
			else:
				l.debug("appending symbolic condition for length %s", i)
				if first_symbolic is None:
					first_symbolic = i

				remaining_symbolic -= 1
				len_parts.append(symexec.And(b == 0, symexec.ULE(len_expr, i)))
				i += 1

		if first_symbolic is not None:
			self.state.add_constraints(len_expr >= first_symbolic)
			self.state.add_constraints(symexec.Or(*len_parts))
		else:
			self.state.add_constraints(len_expr == i)

		self.exit_return(len_expr)
