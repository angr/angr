import simuvex

######################################
# NoReturnUnconstrained
# Use in places you would put ReturnUnconstrained as a default action
# But the function shouldn't actually return
######################################

use_cases = {'exit_group', 'exit', 'abort', 'longjmp', 'pthread_exit', 'siglongjmp'}

class NoReturnUnconstrained(simuvex.SimProcedure): #pylint:disable=redefined-builtin
    NO_RET = True
    def run(self): #pylint:disable=unused-argument
        return
