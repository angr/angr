import simuvex
from simuvex.s_type import SimTypeFd

import logging
l = logging.getLogger("simuvex.procedures.fileno")

######################################
# memset
######################################

class fileno(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, f):
        self.argument_types = {0: SimTypeFd()}
        self.return_type = SimTypeFd()
        return f
