import claripy
import angr

######################################
# fmod
######################################


class fmod(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, x, y):
        # both x and y are double
        x = _raw_ast(x)
        y = _raw_ast(y)
        x = x[63:0].raw_to_fp()
        y = y[63:0].raw_to_fp()

        rm = claripy.fp.RM.RM_TowardsZero
        r = x / y
        quotient = claripy.fpToSBV(rm, r, 64)
        remainder = x - y * quotient.val_to_fp(None)
        return remainder.raw_to_bv()


from ...state_plugins.sim_action_object import _raw_ast
