import angr
import logging

l = logging.getLogger(name=__name__)

class strrchr(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, s_addr, c_int, s_strlen=None):
        strchr = angr.SIM_PROCEDURES['libc']['strchr']
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        s_strlen = self.inline_call(strlen, s_addr)
        l_addr = self.inline_call(strchr, s_addr + s_strlen.ret_expr, c_int).ret_expr
        s_addr = self.inline_call(strchr, s_addr, c_int).ret_expr

        while self.inline_call(strchr, s_addr + 1, c_int).ret_expr is not l_addr:
            s_addr = self.inline_call(strchr, s_addr + 1, c_int).ret_expr

        return s_addr
