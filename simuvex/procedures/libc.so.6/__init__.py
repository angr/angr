import simuvex

class SimStateLibc(simuvex.SimStatePlugin):
	def __init__(self, heap_location=0xbfff0000):
		simuvex.SimStatePlugin.__init__(self)
		self.heap_location = heap_location

	def copy(self):
		return SimStateLibc(self.heap_location)

simuvex.SimStatePlugin.register_default('libc', SimStateLibc)
