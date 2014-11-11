import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def analyze(self, fd, dst, length):
		data = self.state.posix.read(fd, self.state.se.any_int(length))
		self.state.store_mem(dst, data)
		return length
