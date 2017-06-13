import angr

######################################
# bind (but not really)
######################################
import logging
l = logging.getLogger("angr.procedures.libc___so___6.bind")

class bind(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, fd): #pylint:disable=unused-argument
        return self.state.se.Unconstrained('bind', self.state.arch.bits)
