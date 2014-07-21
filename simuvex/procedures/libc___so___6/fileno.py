import simuvex

import logging
l = logging.getLogger("simuvex.procedures.fileno")

######################################
# memset
######################################

class fileno(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		self.exit_return(self.state.claripy.BitVecVal(0, self.state.arch.bits))
