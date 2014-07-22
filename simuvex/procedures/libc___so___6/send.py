import simuvex

######################################
# send
######################################

# ssize_t send(int socket, const void *buffer, size_t length, int flags);

class send(simuvex.SimProcedure):
	def __init__(self):
		#socket fd
		fd = self.get_arg_value(0)
		
		#source of data
		sim_src = self.get_arg_value(1)
		
		#len of shit
		sim_length = self.get_arg_value(2)
		
		#flags
		flags = self.get_arg_value(3)
		
		#import ipdb; ipdb.set_trace()
		# to support symbolic length, we would have to support symbolic memory writes
		if sim_length.is_symbolic():
			length = 200
			# NOTE: if left as symbolic it get's caught downstream on range(0, numbytes)
			print "Fuck your symbolic length, I made it 200....Fix this please"
		elif sim_length.is_symbolic() == False:
			length = sim_length.any()
			
		if length > 2000:
			raise Exception("Fuck your large ass write ( > 2000)")
		
		## TODO handle errors
		
		if length > 0:
			data = self.state.mem_expr(sim_src, length)
			#TODO: Need some way to determine file_type - will most likely come later when we take care of all the structure junk
			#file_type =  self.state['posix'].ftype(fd)
                      	length = self.state['posix'].write(fd.expr, data, length)
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src, data, length, (), ()))

			
			
			
			
		self.exit_return(sim_length.expr)	
		#self.set_return_expr(sim_length.expr)
		#if ret_expr is not None:
			#self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))

