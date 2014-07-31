import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		self.return_type = SimTypeInt(32, True)
		plugin = self.state['posix']
		
		length = self.state.arch.bits
		
		data = plugin.read(0,1)
		data = data.zero_extend(self.state.arch.bits-data.size())
		self.ret(data)
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
	
