import simuvex

######################################
# bind (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.bind")

class bind(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd): #pylint:disable=unused-argument
        return self.state.se.Unconstrained('bind', self.state.arch.bits)
