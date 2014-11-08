import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
	def analyze(self):
		fd = self.arg(0)
		src = self.arg(1)
		length = self.arg(2)

		data = self.state.mem_expr(src, length)
		length = self.state['posix'].write(fd, data, length)

		return length
