import simuvex

######################################
# socket
######################################

class socket(simuvex.SimProcedure):
	def analyze(self):
		# TODO: Handling parameters
		plugin = self.state['posix']

		sock_type = self.arg(1)
		sock_type = self.state.se.any_int(sock_type)
		# TODO handle errors and symbolic path
		fd = plugin.open("socket_socket", "rw")

		#if type is 0, it's UDP so create a socket for it, if not then it's 1 and we create a socket later in accept()
		if sock_type is 0:
			plugin.back_with_pcap(fd)
		plugin.add_socket(fd)
		return fd
