import simuvex
import logging

l = logging.getLogger("simuvex.procedures.sprintf")

######################################
# sprintf
######################################

import math

class sprintf(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		dst_ptr = self.get_arg_expr(0)
		format_ptr = self.get_arg_expr(1)
		first_arg = self.get_arg_expr(2)

		strlen = simuvex.SimProcedures['libc.so.6']['strlen']

		l.debug("WTF")

		format_len = self.inline_call(strlen, format_ptr).ret_expr
		if format_len.symbolic:
			raise Exception("ZOMG, symbolic format strings? Are you joking?")

		format_value = self.state.mem_value(format_ptr, self.state.expr_value(format_len).any(), endness="Iend_BE")
		if format_value.is_symbolic():
			raise Exception("ZOMG, symbolic format strings? Are you joking?")
		format_str = format_value.any_str()

		# get the pieces
		if format_str == "%d":
			# our string
			max_bits = 96
			new_str = self.state.new_symbolic("sprintf_str", max_bits)
			old_str = self.state.mem_expr(dst_ptr, max_bits/8, endness="Iend_BE")

			l.debug("INTEGER")
			digits = [ ]
			for i in [ 10**i for i in range(0, 10) ]:
				digit = ((first_arg / i) % 10 + 0x30)[7:0]
				digits.append(digit)
			digits.reverse()
			digits.append(self.state.claripy.BitVecVal(0, 8))

			# figure out how many will actually be written
			num_constraints = [ ]
			for i,j in [ (10**k/10*10, 10**(k+1)) for k in [ _ - 1 for _ in range(1, 11) ] ]:
				offset = int(9 - math.floor(math.log(i+1, 10)))
				actual_bytes = digits[offset:]

				if len(actual_bytes) > 1: digit_str = self.state.claripy.Concat(*actual_bytes)
				else: digit_str = actual_bytes[0]

				bits_written = len(actual_bytes)*8

				num_constraints.append(self.state.claripy.And(
												self.state.claripy.UGE(first_arg, self.state.claripy.BitVecVal(i, first_arg.size())),
												self.state.claripy.ULE(first_arg, self.state.claripy.BitVecVal(j-1, first_arg.size())),
												new_str[max_bits-1 : max_bits-bits_written] == digit_str,
												new_str[max_bits-bits_written : 0] == old_str[max_bits-bits_written : 0]
											))

			self.state.add_constraints(self.state.Or(*num_constraints))
		elif format_str == "%c":
			new_str = self.state.Concat(first_arg[7:0], self.state.claripy.BitVecVal(0, 8))
		elif format_str == "%s=":
			first_strlen = self.inline_call(strlen, first_arg)
			if first_strlen.ret_expr.symbolic:
				self.exit_return(self.state.new_symbolic("sprintf_fail", self.state.arch.bits))
				return

			new_str = self.state.claripy.Concat(self.state.mem_expr(first_arg, first_strlen.ret_expr.eval(), endness='Iend_BE'), self.state.claripy.BitVecVal(0x3d00, 16))
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, self.state.expr_value(first_arg), self.state.expr_value(first_strlen.ret_expr), first_strlen.ret_expr.eval()))
		elif format_str == "%%%ds %%%ds %%%ds":
			if first_arg.symbolic or self.get_arg_expr(3).symbolic or self.get_arg_expr(4).symbolic:
				l.debug("Symbolic args. Hackin' out.")
				a = 5
				b = 8192
				c = 12
			else:
				a = first_arg.eval()
				b = self.get_arg_expr(3).eval()
				c = self.get_arg_expr(4).eval()

			new_str = self.state.new_bvv(format_str % (a,b,c) + "\x00")
		elif format_str == "Basic %s\r\n":
			str_ptr = first_arg
			str_len = self.state.expr_value(self.inline_call(strlen, str_ptr).ret_expr)

			if not str_len.is_unique():
				new_str = self.state.new_bvv("Basic POOP\r\n\x00")
			else:
				pieces = [ ]
				pieces.append(self.state.new_bvv("Basic "))
				if str_len.any() != 0:
					pieces.append(self.state.mem_expr(str_ptr, str_len.any()))
				pieces.append(self.state.new_bvv("\r\n\x00"))

				new_str = self.state.claripy.Concat(*pieces)
		elif format_str == '<HTML><HEAD><TITLE>%d %s</TITLE></HEAD>\n<BODY BGCOLOR="#cc9999"><H4>%d %s</H4>\n':
			new_str = self.state.new_bvv("THIS IS THE START OF A (ERROR?) MESSAGE THAT'S RETURNED FROM SOMEWHERE\x00")
		elif format_str == '%s\n</BODY></HTML>\n':
			new_str = self.state.new_bvv("THE END OF AN HTML PAGE\x00")
		else:
			if simuvex.o.SYMBOLIC in self.state.options:
				raise Exception("Unsupported format string: %r" % format_str)
			new_str = self.state.new_bvv("\x00")

		self.state.store_mem(dst_ptr, new_str)

		# TODO: actual value
		self.exit_return(self.state.new_symbolic("sprintf_ret", self.state.arch.bits))
