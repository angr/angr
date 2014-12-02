import simuvex

class receive(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def run(self, fd, buf, count, rx_bytes):
		if self.state.satisfiable(extra_constraints=[count != 0]):
			data = self.state.posix.read(fd, count)
			self.state.store_mem(buf, data, size=count)

		self.state.store_mem(rx_bytes, count, condition=rx_bytes != 0)

		# TODO: receive failure
		return self.state.se.BVV(0, self.state.arch.bits)
