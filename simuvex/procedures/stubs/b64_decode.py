import simuvex

class b64_decode(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		src = self.get_arg_expr(0)
		dst = self.get_arg_expr(1)
		length = self.get_arg_expr(2)

		strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']

		cpy = self.inline_call(strncpy, dst, src, length)
		self.state.store_mem(dst+16, self.state.BVV(0, 8))
		self.exit_return(cpy.ret_expr)
#
#		if length.is_symbolic():
#			raise Exception("SYMBOLIC LENGTH WTF")
#
#		ln = length.se.any()
#		full_str = self.state.mem_expr(src, ln)
#
#		for i in range(ln/4):
#			part = se.Extract(ln*8 - i*4*8 - 1, ln*8 - (i+1)*4*8, full_str)
#
#
#
#
#
#		memcpy = simuvex.SimProcedures['libc.so.6']['memcpy']
#
#		fmt = self.get_arg_expr(1) #pylint:disable=unused-variable
#		one = self.get_arg_expr(2)
#		two = self.get_arg_expr(3)
#		three = self.get_arg_expr(4)
#
#		self.inline_call(memcpy, one, src, 5)
#		self.state.store_mem(one+4, self.state.BVV(0, 8))
#		self.inline_call(memcpy, two, src+6, 8192)
#		self.state.store_mem(two+8191, self.state.BVV(0, 8))
#		self.inline_call(memcpy, three, src+6+8193, 12)
#		self.state.store_mem(three+11, self.state.BVV(0, 8))
#
#		if simuvex.o.SYMBOLIC in self.state.options:
#			crazy_str = "index.asp?authorization=M3NhZG1pbjoyNzk4ODMwMw==&yan=yes\x00"
#			self.state.add_constraints(self.state.mem_expr(two, len(crazy_str)) == self.state.BVV(crazy_str))
#
#		self.exit_return(self.state.BVV(3))
