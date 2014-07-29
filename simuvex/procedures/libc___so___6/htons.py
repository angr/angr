import simuvex
import socket
######################################
# htons (yes, really)
######################################


class htons(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
	
		to_convert = self.arg(0)
		if self.state.se.symbolic(to_convert) == False:
			to_convert = socket.htons(self.state.se.any_int(to_convert))
		self.ret(to_convert)

