import simuvex
import logging

l = logging.getLogger("simuvex.procedures.libc.inet_ntoa")


class inet_ntoa(simuvex.SimProcedure):
    def __init__(self):  # pylint: disable=W0231,
        addr = self.get_arg_expr(0)
        #TODO: return an IP address string

        ret_expr = self.state.new_symbolic("inet_ntoa_ret",
                                           self.state.arch.bits)
        self.exit_return(ret_expr)
