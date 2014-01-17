import simuvex

######################################
# strcmp
######################################

class strcmp(simuvex.SimProcedure):
	def __init__(self):
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		self.exit_return()
