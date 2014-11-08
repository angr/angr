import simuvex

######################################
# __vsnprintf
######################################

class vsnprintf(simuvex.SimProcedure):
	def analyze(self):
		# This function returns
		# Add another exit to the retn_addr that is at the top of the stack now
		str_ptr = self.arg(0)
		size = self.arg(1)
		format = self.arg(2)
		ap = self.arg(3)
		return size - 1
