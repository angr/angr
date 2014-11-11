import simuvex

######################################
# exit
######################################

class exit(simuvex.SimProcedure): #pylint:disable=redefined-builtin
	#pylint:disable=arguments-differ

	NO_RET = True
	def analyze(self, exit_code): #pylint:disable=unused-argument
		return
