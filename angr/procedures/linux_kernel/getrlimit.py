import logging
import angr

######################################
# getrlimit
######################################

l = logging.getLogger("angr.SimProcedures")
#pylint:disable=redefined-builtin,arguments-differ
class getrlimit(angr.SimProcedure):

    IS_SYSCALL = True

    def run(self, resource, rlim):
        #import ipdb; ipdb.set_trace()

        if self.state.se.eval(resource) == 3:  # RLIMIT_STACK
            l.debug('running getrlimit(RLIMIT_STACK)')
            self.state.memory.store(rlim, 8388608, 8) # rlim_cur
            self.state.memory.store(rlim+8, self.state.se.Unconstrained("rlim_max", 8*8, key=('api', 'rlimit', 'stack')))
            return 0
        else:
            l.debug('running getrlimit(other)')
            return self.state.se.Unconstrained("rlimit", self.state.arch.bits, key=('api', 'rlimit', 'other'))
