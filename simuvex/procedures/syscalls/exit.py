import simuvex

######################################
# exit
######################################

class exit(simuvex.SimProcedure): #pylint:disable=redefined-builtin
	NO_RET = True
	def analyze(self):
		# no exits from this block
		return

