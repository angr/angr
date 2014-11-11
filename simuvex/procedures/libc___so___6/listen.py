import simuvex

######################################
# listen (but not really)
######################################
import logging
l = logging.getLogger("simuvex.procedures.libc.listen")

class listen(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sockfd, backlog): #pylint:disable=unused-argument
        return self.state.se.Unconstrained('listen', self.state.arch.bits)

