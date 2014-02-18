import simuvex

max_mem_per_variable = 2 ** 16

class SimStateLibc(simuvex.SimStatePlugin):
	__slots__ = [ 'heap_location' ]

	def __init__(self, heap_location=0xbfff0000):
		simuvex.SimStatePlugin.__init__(self)
		self.heap_location = heap_location

	def copy(self):
		return SimStateLibc(self.heap_location)

	def merge(self, others, merge_flag, flag_values):
		self.heap_location = max(o.heap_location for o in others)
		return [ ]

simuvex.SimStatePlugin.register_default('libc', SimStateLibc)
