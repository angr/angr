import archinfo.arch_arm
import claripy
import angr

######################################
# div
######################################


class div(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, x, y):
        # in ARM, div function requires 3 arguments
        if archinfo.arch_arm.is_arm_arch(self.arch):
            ptr = _raw_ast(self.arg(0))
            x = _raw_ast(self.arg(1))
            y = _raw_ast(self.arg(2))
            x = x[31:0]
            y = y[31:0]
            quotient = x / y
            remainder = x % y
            self.state.memory.store(ptr, quotient, endness=self.arch.memory_endness)
            self.state.memory.store(ptr + self.arch.bytes, remainder, endness=self.arch.memory_endness)
            return ptr
        else:
            x = _raw_ast(x)
            y = _raw_ast(y)
            x = x[31:0]
            y = y[31:0]
            quotient = x / y
            remainder = x % y
            return claripy.Concat(quotient, remainder)


from ...state_plugins.sim_action_object import _raw_ast
