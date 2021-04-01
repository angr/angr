import claripy
import angr

######################################
# div
######################################


class div(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, x, y):
        x = _raw_ast(x)
        y = _raw_ast(y)
        x = x[31:0]
        y = y[31:0]
        remainder = x / y
        quotient = x % y
        return claripy.Concat(remainder, quotient)


from ...state_plugins.sim_action_object import _raw_ast
