import simuvex

class receive(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def run(self, fd, buf, count, rx_bytes):
		max_size = self.state.BV('receive_length', self.state.arch.bits)
		self.state.add_constraints(max_size <= count)

		if self.state.satisfiable(extra_constraints=[count != 0]):
			data = self.state.posix.read(fd, count)
			self.state.store_mem(buf, data, size=max_size)

		self.state.store_mem(rx_bytes, max_size, condition=rx_bytes != 0)

		# TODO: receive failure
		return self.state.se.BVV(0, self.state.arch.bits)
