import simuvex

######################################
# recv
######################################

class recv(simuvex.SimProcedure):
	
	#def __init__(self): # pylint: disable=W0231
		## TODO: Symbolic fd
		#fd = self.arg(0)
		#dst = self.arg(1)
		#length = self.arg(1)
		#plugin = self.state['posix']

		## TODO handle errors
		#data = plugin.read(fd, length)
		#self.state.store_mem(dst, data)
		#self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, dst, data, length))
		#self.ret(length)
		
    def __init__(self): # pylint: disable=W0231
        # TODO: Symbolic fd
        fd = self.arg(0)
        
        #destination of the recv'd data
        sim_dst = self.arg(1)
        
        #size of info recv'd
        sim_length = self.arg(2)
        
        plugin = self.state['posix']
        
        if self.state.se.symbolic(sim_length):
		length = 200
		# NOTE: if left as symbolic it get's caught downstream on range(0, numbytes)
		print "Dude your symbolic length would've caused issues so I just made it 200. Fix me at some point though"
	else:
		length = self.state.any_int(sim_length)
			
	if length > 2000:
		raise Exception("No way you're allowed to receive that much data ( > 2000)")

	data = plugin.read(fd.expr, length)
	#import ipdb;ipdb.set_trace()
	#if plugin.get_file(fd.any()).pflag:
		#import ipdb;ipdb.set_trace()
		#pcap = plugin.get_file(fd.any()).pcap
		#plength, pdata = pcap.out_streams[pcap.pos]
		#length = min(length, plength)
		#data = pdata[pcap.pos:length]
		#pcap.pos += 1
		
        # TODO handle errors
        
        self.state.store_mem(sim_dst, data)
        self.add_refs(simuvex.SimMemWrite(self.addr, self.stmt_from, sim_dst, data, length))

        self.ret(length)


