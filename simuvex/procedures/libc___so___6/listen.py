import simuvex

######################################
# listen (but not really)
######################################


class listen(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
	
		# who even cares? Just return that shit, sure man, we called bind...whatever lol
		print("I'm listening. (JK I didn't actually do anything)")
		self.ret()

