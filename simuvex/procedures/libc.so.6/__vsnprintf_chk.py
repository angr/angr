import simuvex

######################################
# __vsnprintf (chk version)
######################################

class __vsnprintf_chk(simuvex.SimProcedure):
	def __init__(self):
		# This function returns
		# Add another exit to the retn_addr that is at the top of the stack now
		retn_addr = self.do_return()
		# TODO: What if the return address cannot be concretized? Then it won't add any exit there
		self.add_exits(simuvex.s_exit.SimExit(expr = retn_addr, state = self.state))
