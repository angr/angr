import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
	def analyze(self):
		self.return_type = SimTypeInt(32, True)
		plugin = self.state['posix']

		_ = plugin.pos(0)
		data = plugin.read(0,1)
		data = data.zero_extend(self.state.arch.bits-data.size())
		self.ret(data)
