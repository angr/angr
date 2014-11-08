import simuvex

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
	def analyze(self):
		string = self.arg(0)

		plugin = self.state['posix']
		plugin.write(1, string[7:0], 1)

		# TODO: return values
		return string[7:0].zero_extend(self.state.arch.bits - 8)
