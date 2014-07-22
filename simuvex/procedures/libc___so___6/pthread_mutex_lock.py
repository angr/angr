import simuvex

######################################
# Doing nothing
######################################

class pthread_mutex_lock(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231,
		_ = self.arg(0)
		self.ret()
