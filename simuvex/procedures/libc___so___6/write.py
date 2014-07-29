import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
	def __init__(self):
		fd = self.arg(0)
		sim_src = self.arg(1)
		sim_length = self.arg(2)
		
		#import ipdb;ipdb.set_trace()
		# to support symbolic length, we would have to support symbolic memory writes
		if self.state.se.symbolic(sim_length):
			length = 200
			lenth = sim_length.any()
			# NOTE: if left as symbolic it get's caught downstream on range(0, numbytes)
			print "Fuck your symbolic length, I made it 200....Fix this please"
		elif self.state.se.symbolic(sim_length) == False:
			length = sim_length.any()
			
		if length > 2000:
			raise Exception("Fuck your large ass write ( > 2000)")
		
		## TODO handle errors
		
		if length > 0:
			data = self.state.mem_expr(sim_src, length)
			#TODO: Need some way to determine file_type - will most likely come later when we take care of all the structure junk
			#file_type =  self.state['posix'].ftype(fd)
			#TODO: Once we know the file_type we can call some exists() thing and then check the type - if it's a socket we can call open instead of write if say we wanted a file
			length = self.state['posix'].write(fd, data, length)
			self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src, data, length, (), ()))

			
			
			
			
		import ipdb; ipdb.set_trace()
		self.ret(sim_length)	
		#self.set_return_expr(sim_length.expr)
		#if ret_expr is not None:
			#self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))

