import simuvex

######################################
# free
######################################
class free(simuvex.SimProcedure):
	def __init__(self):
		# TODO: if the return address cannot be concretized?
		self.exit_return()
