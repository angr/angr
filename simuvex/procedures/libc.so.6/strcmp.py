import simuvex
import symexec

import logging
l = logging.getLogger("simuvex.procedures.strcmp")

######################################
# strcmp
######################################

# TODO: bigger
max_str_size = 16

def analyze_str(str_base, state):
	symbolic = [ ]
	nonzero = [ ]
	zero = [ ]

	for i in range(0, max_str_size):
		b = state.mem_value(str_base.expr + i, 1)
		if b.is_symbolic():
			symbolic.append(i)
		elif b.any() != 0:
			nonzero.append(i)
		else:
			zero.append(i)

	return symbolic, nonzero, zero

class strcmp(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		a = self.get_arg_value(0)
		b = self.get_arg_value(1)

		# figure out the list of symbolic bytes, concrete bytes, and concrete \0 bytes in the strings
		a_symbolic, _, a_zero = analyze_str(a, self.state)
		b_symbolic, _, b_zero = analyze_str(b, self.state)

		any_zeroes = a_zero + b_zero
		all_symbolic = sorted(tuple((set(a_symbolic) & set(b_symbolic))))
		any_symbolic = a_symbolic + b_symbolic

		# heuristically determine the string size
		# TODO: this is extremely limiting and should be reconsidered
		if len(any_zeroes) > 0:
			str_size = min(any_zeroes)
		elif len(all_symbolic) > 0:
			# TODO: might make the string *too* small
			str_size = all_symbolic[0]
		else:
			str_size = min(any_symbolic)

		l.debug("Determined a str_size of %d", str_size)

		# the bytes
		a_bytes = [ ]
		b_bytes = [ ]
		for i in range(str_size + 1):
			a_bytes.append(self.state.mem_expr(a.expr + i, 1))
			b_bytes.append(self.state.mem_expr(b.expr + i, 1))

		# make the constraints
		match_constraint = symexec.And(*[ a_byte == b_byte for a_byte, b_byte in zip(a_bytes, b_bytes) ])
		nomatch_constraint = symexec.Not(match_constraint)

		#l.debug("match constraints: %s", match_constraint)
		#l.debug("nomatch constraints: %s", nomatch_constraint)

		# TODO: FIXME: this is a hax
		# TODO: add refs
		match_state = self.state.copy_exact()
		match_state.add_constraints(match_constraint)

		nomatch_state = self.state
		nomatch_state.add_constraints(nomatch_constraint)

		self.state = match_state
		self.exit_return(symexec.BitVecVal(0, self.state.arch.bits))
		self.state = nomatch_state
		self.exit_return(symexec.BitVecVal(1, self.state.arch.bits)) # TODO: proper return value
