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
#<<<<<<< HEAD
		self.ret(fd)
#=======
		#plugin.add_socket(fd)
		
		##NOTE:NOTE:NOTE:NOTE: SHOULDN'T ACTUALLY BE HERE LOLOLOLOLOLOL SHOULD BE IN ACCEPT.PY
		##plugin.backme(fd)

		
		#self.exit_return(simuvex.SimValue(fd).expr)
#>>>>>>> 881fea513fdf4b13beef0db413383b53d4eaa60c
