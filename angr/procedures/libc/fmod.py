import claripy
import angr

######################################
# fmod
######################################


class fmod(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, x, y):
        val_len = self.arch.bytes * self.arch.byte_width
        # both x and y are double
        x = _raw_ast(x)
        y = _raw_ast(y)

        if self.arch.memory_endness == 'Iend_LE':
            x = x[63:64 - val_len].raw_to_fp()
            y = y[63:64 - val_len].raw_to_fp()
        else:
            x = x[63:0].raw_to_fp()
            y = y[63:0].raw_to_fp()

        rm = claripy.fp.RM.RM_TowardsZero
        r = x / y
        quotient = claripy.fpToSBV(rm, r, val_len)
        remainder = x - y * quotient.val_to_fp(None)
        return remainder


from ...state_plugins.sim_action_object import _raw_ast
