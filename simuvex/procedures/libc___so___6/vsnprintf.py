import simuvex

######################################
# __vsnprintf
######################################

class vsnprintf(simuvex.SimProcedure):
	def __init__(self):
		# This function returns
		# Add another exit to the retn_addr that is at the top of the stack now
		str_ptr = self.get_arg_value(0)
		size = self.get_arg_value(1)
		format = self.get_arg_value(2)
		ap = self.get_arg_value(3)
		self.exit_return(size.expr - 1)
