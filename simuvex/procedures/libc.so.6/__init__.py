import simuvex

class SimStateLibc(simuvex.SimStatePlugin):
	def __init__(self, heap_location=0xbfff0000, heap_id='heap_id'):
		simuvex.SimStatePlugin.__init__(self)
		self.heap_location = heap_location
                self.max_mem_per_variable = 2 ** 16
                self.heap_id = heap_id

	def copy(self):
		return SimStateLibc(self.heap_location)

	def merge(self, other, merge_flag, flag_us_value):
		self.heap_location = max(self.heap_location, other.heap_location)

simuvex.SimStatePlugin.register_default('libc', SimStateLibc)
