import simuvex
import itertools

######################################
# calloc
######################################

calloc_mem_counter = itertools.count()

class calloc(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		plugin = self.state.get_plugin('libc')

		sim_nmemb = self.arg(0)
		sim_size = self.arg(1)

		if sim_nmemb.symbolic:
			# TODO: find a better way
			nmemb = self.state.max(sim_nmemb)
		else:
			nmemb = self.state.any(sim_nmemb)

		if sim_size.is_symbolic():
			# TODO: find a better way
			size = self.state.max(sim_size)
		else:
			size = self.state.any(sim_size)

		final_size = size * nmemb * 8
		if final_size > plugin.max_variable_size:
			final_size = plugin.max_variable_size

		addr = plugin.heap_location
		plugin.heap_location += final_size
		v = self.state.BVV(0, final_size)
		self.state.store_mem(addr, v)

		self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, addr, v, final_size, [], [], [], []))
		self.ret(addr)
