import simuvex

######################################
# __isoc99_scanf
######################################

class __isoc99_scanf(simuvex.SimProcedure):
	def __init__(self):
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		self.exit_return()
