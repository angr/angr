import simuvex

import itertools
rand_count = itertools.count()

class random(simuvex.SimProcedure):
	#pylint:disable=arguments-differ

	def run(self, buf, count, rnd_bytes):
		# return code
		r = self.state.se.ite_cases((
				(self.state.cgc.addr_invalid(buf), self.state.cgc.EFAULT),
				(self.state.cgc.addr_invalid(rnd_bytes), self.state.cgc.EFAULT),
			), self.state.se.BVV(0, self.state.arch.bits))

		if self.state.satisfiable(extra_constraints=[count!=0]):
			self.state.store_mem(buf, self.state.se.BV('random_%d' % rand_count.next(), self.state.se.max_int(count*8)), size=count)
		self.state.store(rnd_bytes, count)

		return r
