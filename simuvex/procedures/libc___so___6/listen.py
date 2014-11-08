import simuvex

######################################
# listen (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.listen")

class listen(simuvex.SimProcedure):
    def analyze(self):
        return self.state.se.Unconstrained('listen', self.state.arch.bits)

