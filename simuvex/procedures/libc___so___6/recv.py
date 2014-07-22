import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        fd = self.get_arg_value(0)
        
        #destination of the recv'd data
        sim_dst = self.get_arg_value(1)
        
        #size of info recv'd
        sim_length = self.get_arg_value(2)
        
        plugin = self.state['posix']
        
        if sim_length.is_symbolic():
		length = 200
		# NOTE: if left as symbolic it get's caught downstream on range(0, numbytes)
		print "Dude your symbolic length would've caused issues so I just made it 200. Fix me at some point though"
	elif sim_length.is_symbolic() == False:
		length = sim_length.any()
			
	if length > 2000:
		raise Exception("No way you're allowed to receive that much data ( > 2000)")


        # TODO handle errors
        data = plugin.read(fd.expr, length)
        self.state.store_mem(sim_dst.expr, data)
        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, self.state.expr_value(data), length))

        self.exit_return(simuvex.SimValue(length).expr)

