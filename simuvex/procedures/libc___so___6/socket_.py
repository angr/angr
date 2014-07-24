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
		plugin.add_socket(fd)
		
		#NOTE:NOTE:NOTE:NOTE: SHOULDN'T ACTUALLY BE HERE LOLOLOLOLOLOL SHOULD BE IN ACCEPT.PY
		#plugin.backme(fd)

		
		self.exit_return(simuvex.SimValue(fd).expr)
