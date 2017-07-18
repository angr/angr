import angr

######################################
# listen (but not really)
######################################
import logging
l = logging.getLogger("angr.procedures.libc___so___6.listen")

class listen(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, sockfd, backlog): #pylint:disable=unused-argument
        return self.state.se.Unconstrained('listen', self.state.arch.bits)

