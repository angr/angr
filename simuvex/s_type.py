class SimType(object):
	'''
	SimType exists to track type information for SimProcedures.
	'''

	def __init__(self, label):
		'''
		@param label: the type label
		'''
		self.label = label

class SimTypeLength(SimType):
	'''
	SimTypeLength is a type that specifies the length of some buffer in memory.
	'''

	def __init__(self, label, addr, length):
		'''
		@param label: the type label
		@param addr: the memory address (expression)
		@param length: the length (expression)
		'''
		SimType.__init__(self, label)
		self.addr = addr
		self.length = length
