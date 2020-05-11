import logging
import angr

######################################
# getrlimit
######################################

l = logging.getLogger(name=__name__)
#pylint:disable=redefined-builtin,arguments-differ
class getrlimit(angr.SimProcedure):

    def run(self, resource, rlim):

        if self.state.solver.eval(resource) == 3:  # RLIMIT_STACK
            l.debug('running getrlimit(RLIMIT_STACK)')
            self.state.memory.store(rlim, 8388608, 8) # rlim_cur
            self.state.memory.store(rlim+8, self.state.solver.Unconstrained("rlim_max", 8*8, key=('api', 'rlimit', 'stack')))
            return 0
        else:
            l.debug('running getrlimit(other)')
            return self.state.solver.Unconstrained("rlimit", self.state.arch.bits, key=('api', 'rlimit', 'other'))

class ugetrlimit(getrlimit):
    pass
