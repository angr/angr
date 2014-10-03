import simuvex
from simuvex.s_type import SimTypeString
import logging

l = logging.getLogger("simuvex.procedures.libc.inet_ntoa")


class inet_ntoa(simuvex.SimProcedure):
    def __init__(self): # pylint: disable=W0231,
        # arg types: struct....... :(
        self.return_type = self.ty_ptr(SimTypeString())

        #TODO: return an IP address string
        addr = self.arg(0)
        ret_expr = self.state.BV("inet_ntoa_ret", self.state.arch.bits)
        self.ret(ret_expr)
