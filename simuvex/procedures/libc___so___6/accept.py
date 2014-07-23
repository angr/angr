import simuvex

######################################
# accept (but not really)
######################################

class accept(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231

	
		#### IGNORE ALL ARGUMENTS FOR NOW AND JUST RETURN A FD SOCKET
		## TODO: Symbolic fd
		## this is the name for now
		sockfd = self.get_arg_value(0)
		#this is the mode for now
		sockaddr_struct_ptr = self.get_arg_value(1)
		#socklen_t_addrlen = self.get_arg_value(2)
		## TODO handle mode if flags == O_CREAT

		##NOTE: might be misinterpretting 'falgs' here
		#flags = 'wr'
		
		plugin = self.state['posix']

		# TODO handle errors and symbolic path
		key = plugin.open(sockfd.expr, sockaddr_struct_ptr.expr)
		#add this socket to the SimStateSystem list of sockets
		plugin.add_socket(key)
		
		'''should back the SimFile associated with this key by the first pcap on the pcap queue
		and then transfer that pcap to the list/queue of used_pcaps'''
		plugin.backme(key)
		
		self.exit_return(simuvex.SimValue(key).expr)

