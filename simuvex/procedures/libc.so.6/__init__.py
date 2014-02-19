import simuvex

max_mem_per_variable = 2 ** 16

class SimStateLibc(simuvex.SimStatePlugin):
	__slots__ = [ 'heap_location', 'max_str_size' ]

	def __init__(self, heap_location=0xc0000000, max_str_size = 16):
		simuvex.SimStatePlugin.__init__(self)
		self.heap_location = heap_location
		self.max_str_size = max_str_size

	def copy(self):
		return SimStateLibc(self.heap_location)

	def merge(self, others, merge_flag, flag_values):
		self.heap_location = max(o.heap_location for o in others)
		return [ ]

simuvex.SimStatePlugin.register_default('libc', SimStateLibc)
