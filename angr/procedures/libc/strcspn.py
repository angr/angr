import angr
import logging

l = logging.getLogger(name=__name__)


class strcspn(angr.SimProcedure):
    # simple version, only can deal with single valued string
    # pylint:disable=arguments-differ

    def run(self, a_addr, b_addr):  # pylint:disable=arguments-differ
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncmp = angr.SIM_PROCEDURES['libc']['strncmp']

        a_strlen = self.inline_call(strlen, a_addr)
        b_strlen = self.inline_call(strlen, b_addr)

        a_len = a_strlen.ret_expr
        b_len = b_strlen.ret_expr

        if self.state.solver.single_valued(a_len) and self.state.solver.single_valued(b_len):
            c_a_len = self.state.solver.eval(a_len)
            c_b_len = self.state.solver.eval(b_len)

            for i in range(c_a_len):
                for j in range(c_b_len):
                    ret_expr = self.inline_call(strncmp, a_addr+i, b_addr+j, 1).ret_expr
                    if self.state.solver.single_valued(ret_expr):
                        ret = self.state.solver.eval(ret_expr)
                        if ret == 0:
                            return self.state.solver.BVV(i, self.state.arch.bits)

            return self.state.solver.BVV(c_a_len, self.state.arch.bits)

        else:
            return self.state.solver.BVV(c_a_len, self.state.arch.bits)
