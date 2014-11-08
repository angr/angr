import simuvex
from simuvex.s_type import SimTypeFd

import logging
l = logging.getLogger("simuvex.procedures.fileno")

######################################
# memset
######################################

class fileno(simuvex.SimProcedure):
	def analyze(self):
		self.return_type = SimTypeFd()

		return self.arg(0)
