import simuvex

######################################
# bind (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.bind")

class bind(simuvex.SimProcedure):
    def analyze(self):
        return self.state.se.Unconstrained('bind', self.state.arch.bits)
