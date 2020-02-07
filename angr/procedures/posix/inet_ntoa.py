import angr
from angr.sim_type import SimTypeString
import logging

l = logging.getLogger(name=__name__)


class inet_ntoa(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, addr_in): #pylint:disable=unused-argument
        # arg types: struct....... :(

        #TODO: return an IP address string
        ret_expr = self.state.solver.Unconstrained("inet_ntoa_ret", self.state.arch.bits)
        return ret_expr
