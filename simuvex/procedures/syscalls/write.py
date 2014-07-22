import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
	def __init__(self, ret_expr = None): #pylint:disable=W0231
		fd = self.arg(0)
		src = self.arg(1)
		length = self.arg(2)

		data = self.state.mem_expr(src, length)
		length = self.state['posix'].write(fd, data, length)
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, src, data, length, (), ()))

		self.set_return_expr(length)
		if ret_expr is not None:
			self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
