import angr
from angr.sim_type import SimTypeTop

######################################
# free
######################################
class free(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, ptr): #pylint:disable=unused-argument
        self.argument_types = {0: self.ty_ptr(SimTypeTop())}
        return self.state.solver.Unconstrained('free', self.state.arch.bits)
