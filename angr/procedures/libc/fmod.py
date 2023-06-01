import claripy
import angr
from claripy.ast.fp import FP

######################################
# fmod
######################################


class fmod(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, x, y):
        val_len = self.arch.bytes * self.arch.byte_width
        # both x and y are double
        x = _raw_ast(x)
        y = _raw_ast(y)
        rm = claripy.fp.RM.RM_TowardsZero

        if x.size() != val_len or y.size() != val_len:
            # we need to truncate x or y
            if isinstance(x, FP):
                x = claripy.fpToSBV(rm, x, val_len)
            if isinstance(y, FP):
                y = claripy.fpToSBV(rm, y, val_len)
            if self.arch.memory_endness == "Iend_LE":
                x = x[63 : 64 - val_len]
                y = y[63 : 64 - val_len]
            else:
                x = x[63:0]
                y = y[63:0]

        # ensure both x and y are FPs
        x = x.raw_to_fp()
        y = y.raw_to_fp()

        r = x / y
        quotient = claripy.fpToSBV(rm, r, val_len)
        remainder = x - y * quotient.val_to_fp(None)
        return remainder


from ...state_plugins.sim_action_object import _raw_ast
