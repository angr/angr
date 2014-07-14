import simuvex
from simuvex.s_type import SimTypeString
import logging

l = logging.getLogger("simuvex.procedures.libc.inet_ntoa")


class inet_ntoa(simuvex.SimProcedure):
    def __init__(self):  # pylint: disable=W0231,
        # arg types: struct....... :(
        self.return_type = self.ty_ptr(SimTypeString())
        addr = self.get_arg_expr(0)
        #TODO: return an IP address string

        ret_expr = self.state.new_symbolic("inet_ntoa_ret",
                                           self.state.arch.bits)
        self.exit_return(ret_expr)
