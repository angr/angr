import simuvex
import symexec

######################################
# close
######################################

class close(simuvex.SimProcedure):
        def __init__(self, ret_expr): # pylint: disable=W0231
                # TODO: Symbolic fd
                fd = self.get_arg_value(0)
                plugin = self.state['posix']

                # TODO handle errors
                plugin.close(fd.expr)

                v = symexec.BitVecVal(0, self.state.arch.bits)
                self.set_return_expr(simuvex.SimValue(v))
                # TODO: code referencies?
                self.add_exits(simuvex.SimExit(expr=ret_expr, state=self.state))
