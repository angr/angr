import simuvex

######################################
# putchar
######################################

class putchar(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		string = self.arg(0)
		self.state['posix'].write(1, string[7:0], 1)

		# TODO: return values
		self.ret()
