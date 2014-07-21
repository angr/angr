import simuvex
#from simuvex.s_type import SimTypeLength, SimTypePointer, SimTypeTop
import itertools

######################################
# malloc
######################################

malloc_mem_counter = itertools.count()

class malloc(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		#self.argument_types = {0: SimTypeLength(arch=self.state.arch)}
		#self.return_type = SimTypePointer(SimTypeTop())

		plugin = self.state.get_plugin('libc')
		sim_size = self.arg(0)

		if sim_size.is_symbolic():
			size = sim_size.max()
			if size > plugin.max_variable_size:
				size = plugin.max_variable_size
		else:
			size = sim_size.any() * 8

		addr = plugin.heap_location
		plugin.heap_location += size
		self.ret(addr)
