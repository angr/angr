import simuvex

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		self.ret()
