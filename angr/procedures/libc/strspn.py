import angr
import logging

l = logging.getLogger(name=__name__)

class strspn(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):
        strncmp = angr.SIM_PROCEDURES['libc']['strncmp']
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)
        a_len = a_strlen.ret_expr
        b_len = b_strlen.ret_expr
        c_a_len = self.state.solver.eval(a_len)
        c_b_len = self.state.solver.eval(b_len)

        flag = 0
        for i in range(c_a_len):
            for j in range(c_b_len):
                value = self.inline_call(strncmp, a_addr + i, b_addr + j, 1).ret_expr
                if self.state.solver.eval(value) == 0:
                    flag = 1
            if flag == 0:
                return self.state.solver.BVV(i, self.state.arch.bits)
            flag = 0

        return a_len
