import simuvex
from simuvex.s_type import SimTypeFd

import logging
l = logging.getLogger("simuvex.procedures.fileno")

######################################
# memset
######################################

class fileno(simuvex.SimProcedure):
    def analyze(self):
        self.ret(self.state.BVV(0, self.state.arch.bits))
        self.return_type = SimTypeFd()
