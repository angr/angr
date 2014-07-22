import simuvex

######################################
# socket
######################################

class socket(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
	        # TODO: Handling parameters
		plugin = self.state['posix']

		# TODO handle errors and symbolic path
		fd = plugin.open("socket", "rw")
		self.ret(fd)
