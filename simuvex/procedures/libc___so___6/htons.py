import simuvex
import socket
######################################
# htons (yes, really)
######################################


class htons(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
	
		to_convert = self.get_arg_value(0)
		import ipdb;ipdb.set_trace()
		if to_convert.is_symbolic() == False:
			to_convert = socket.htons(to_convert.any())
		self.exit_return(simuvex.SimValue(to_convert).expr)

