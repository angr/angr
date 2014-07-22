

import simuvex

######################################
# bind (but not really)
######################################




class bind(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
	
		# who even cares? Just return that shit, sure man, we called bind...whatever lol
		print("Yeah man, I totally just called bind (lol)")
		self.exit_return()

