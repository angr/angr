import simuvex

######################################
# NoReturnUnconstrained
# Use in places you would put ReturnUnconstrained as a default action
# But the function shouldn't actually return
######################################

class NoReturnUnconstrained(simuvex.SimProcedure): #pylint:disable=redefined-builtin
    use_cases = {'exit_group', 'exit', 'abort', 'longjmp', 'pthread_exit', 'siglongjmp',
                 '__longjmp_chk', '__siglongjmp_chk', '__assert_fail'}
    NO_RET = True
    def run(self, **kwargs): #pylint:disable=unused-argument
        self.exit(self.state.se.Unconstrained('unconstrained_exit_code', self.state.arch.bits))
