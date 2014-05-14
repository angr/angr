import simuvex
import symexec as se

import logging
l = logging.getLogger("simuvex.procedures.fileno")

######################################
# memset
######################################

class fileno(simuvex.SimProcedure):
	def __init__(self): # pylint: disable=W0231
		self.exit_return(se.BitVecVal(0, self.state.arch.bits))
