import simuvex

######################################
# Doing nothing
######################################


class Nop(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		self.ret()
