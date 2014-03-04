import simuvex
import symexec as se
import logging

l = logging.getLogger("simuvex.procedures.sprintf")

######################################
# sprintf
######################################

import math
import itertools
sprintf_counter = itertools.count()

class sprintf(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		str_ptr = self.get_arg_expr(0)
		format_ptr = self.get_arg_expr(1)
		first_arg = self.get_arg_expr(2)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		l.debug("WTF")

		format_len = self.inline_call(strlen, format_ptr).ret_expr
		if se.is_symbolic(format_len):
			raise Exception("ZOMG, symbolic format strings? Are you joking?")

		format_value = self.state.mem_value(format_ptr, self.state.expr_value(format_len).any(), endness="Iend_BE")
		if format_value.is_symbolic():
			raise Exception("ZOMG, symbolic format strings? Are you joking?")
		format_str = format_value.any_str()

		# get the pieces
		if format_str == "%d\n":
			# our string
			max_bits = 96
			new_str = se.BitVec("sprintf_str_%d" % sprintf_counter.next(), max_bits)

			old_str = self.state.mem_expr(str_ptr, max_bits/8, endness="Iend_BE")

			l.debug("INTEGER")
			digits = [ ]
			for i in [ 10**i for i in range(0, 10) ]:
				digit = se.Extract(7, 0, (first_arg / i) % 10 + 0x30)
				digits.append(digit)
			digits.reverse()
			digits.append(se.BitVecVal(0, 8))

			# figure out how many will actually be written
			num_constraints = [ ]
			for i,j in [ (10**k/10*10, 10**(k+1)) for k in [ _ - 1 for _ in range(1, 11) ] ]:
				offset = int(9 - math.floor(math.log(i+1, 10)))
				actual_bytes = digits[offset:]

				if len(actual_bytes) > 1: digit_str = se.Concat(*actual_bytes)
				else: digit_str = actual_bytes[0]

				bits_written = len(actual_bytes)*8

				num_constraints.append(se.And(
												se.UGE(first_arg, se.BitVecVal(i, first_arg.size())),
												se.ULE(first_arg, se.BitVecVal(j-1, first_arg.size())),
												se.Extract(max_bits-1, max_bits-bits_written, new_str) == digit_str,
												se.Extract(max_bits-bits_written, 0, new_str) == se.Extract(max_bits-bits_written, 0, old_str)
											))

			self.state.add_constraints(se.Or(*num_constraints))
			new_str = se.Concat(new_str, se.BitVec(0x0a, 8))
		elif format_str == "%c":
			new_str = se.Concat(se.Extract(7, 0, first_arg), se.BitVecVal(0, 8))
		else:
			raise Exception("Unsupported format string: %s", format_str)

		self.state.store_mem(str_ptr, new_str)

		# TODO: actual value
		self.exit_return(se.BitVec("sprintf_ret_%d" % sprintf_counter.next(), self.state.arch.bits))
