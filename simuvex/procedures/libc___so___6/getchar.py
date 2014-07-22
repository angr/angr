import simuvex
from simuvex.s_type import SimTypeInt

######################################
# getchar
######################################

class getchar(simuvex.SimProcedure):
	def __init__(self): #pylint:disable=W0231
		self.return_type = SimTypeInt(32, True)
		# TODO: Access different registers on different archs
		# TODO: handle symbolic and static modes
		self.ret()
