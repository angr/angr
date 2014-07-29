import simuvex

######################################
# write
######################################

class write(simuvex.SimProcedure):
#<<<<<<< HEAD
	def __init__(self, ret_expr = None): #pylint:disable=W0231
		fd = self.arg(0)
		src = self.arg(1)
		length = self.arg(2)

		data = self.state.mem_expr(src, length)
		length = self.state['posix'].write(fd, data, length)
		self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, src, data, length, (), ()))

		self.set_return_expr(length)
#=======
	#def __init__(self, ret_expr = None):
		#fd = self.arg(0)
		#sim_src = self.arg(1)
		#sim_length = self.arg(2)
		
	##	import ipdb; ipdb.set_trace()

		## to support symbolic length, we would have to support symbolic memory writes
	
	
		#'''NOTE: wtf is up with this? Even when reporte symbolic it doesn't seem like it should be
		#and alas, .any() gives me the expected value '''
		#if sim_length.is_symbolic():
			#length = sim_length.any()
			## NOTE: if left as symbolic it get's caught downstream on range(0, numbytes)
			#print "Fuck your symbolic length, I made it 200....Fix this please"
		#elif sim_length.is_symbolic() == False:
			#length = sim_length.any()
			
		#if length > 1000:
			#import ipdb;ipdb.set_trace()
			#length = 50
		
		### TODO handle errors
		#if length > 0:
			#data = self.state.mem_expr(sim_src, length)
			##length = self.state['posix'].write(fd, data, length)
			#length = self.state['posix'].write(fd.expr, data, length)
			#self.add_refs(simuvex.SimMemRead(self.addr, self.stmt_from, sim_src, data, length, (), ()))

		#self.set_return_expr(sim_length.expr)
#>>>>>>> 881fea513fdf4b13beef0db413383b53d4eaa60c
		#if ret_expr is not None:
			#self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))

