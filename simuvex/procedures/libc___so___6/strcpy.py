import simuvex

class strcpy(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		strlen = simuvex.SimProcedures['libc.so.6']['strlen']
		strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']

		dst = self.arg(0)
		src = self.arg(1)
		src_len = self.inline_call(strlen, src)

		ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len).ret_expr
		self.ret(ret_expr)

