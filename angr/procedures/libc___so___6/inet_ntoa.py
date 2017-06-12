import simuvex
from simuvex.s_type import SimTypeString
import logging

l = logging.getLogger("simuvex.procedures.libc.inet_ntoa")


class inet_ntoa(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, addr_in): #pylint:disable=unused-argument
        # arg types: struct....... :(
        self.return_type = self.ty_ptr(SimTypeString())

        #TODO: return an IP address string
        ret_expr = self.state.se.Unconstrained("inet_ntoa_ret", self.state.arch.bits)
        return ret_expr
