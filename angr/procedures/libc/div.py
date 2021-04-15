import claripy
import angr

######################################
# div
######################################


class div(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, x, y):
        # in ARM, div function requires 3 arguments
        if self.arch.name == 'ARMHF':
            x = _raw_ast(self.arg(0))
            y = _raw_ast(self.arg(1))
            z = _raw_ast(self.arg(2))
            y = y[31:0]
            z = z[31:0]
            quotient = y / z
            remainder = y % z
            self.state.memory.store(x, quotient)
            self.state.memory.store(x + self.arch.bytes, remainder)
            return x
        else:
            x = _raw_ast(x)
            y = _raw_ast(y)
            x = x[31:0]
            y = y[31:0]
            quotient = x / y
            remainder = x % y
            return claripy.Concat(quotient, remainder)


from ...state_plugins.sim_action_object import _raw_ast
