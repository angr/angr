import angr

######################################
# NoReturnUnconstrained
# Use in places you would put ReturnUnconstrained as a default action
# But the function shouldn't actually return
######################################

class NoReturnUnconstrained(angr.SimProcedure): #pylint:disable=redefined-builtin
    NO_RET = True
    def run(self, **kwargs): #pylint:disable=unused-argument
        self.exit(self.state.solver.Unconstrained('unconstrained_exit_code', self.state.arch.bits))
