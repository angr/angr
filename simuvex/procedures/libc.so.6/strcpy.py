import simuvex
import symexec as se

class strcpy(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']

		dst = self.get_arg_expr(0)
		src = self.get_arg_expr(1)
		src_len = self.inline_call(strlen, src)

		ret_expr = self.inline_call(strncpy, dst, src, se.BitVecVal(src_len.maximum_null+1, self.state.arch.bits), src_len=src_len).ret_expr
		self.exit_return(ret_expr)

