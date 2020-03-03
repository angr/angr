import angr

import logging
l = logging.getLogger(name=__name__)

class strcmp(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, a_addr, b_addr, wchar=False, ignore_case=False, nested_call = False):
        self.state.history.add_call(('strcmp', nested_call, a_addr,b_addr))
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        a_strlen = self.inline_call(strlen, a_addr, wchar=wchar)
        self.state.history.add_call(('strlen', True, a_addr))
        b_strlen = self.inline_call(strlen, b_addr, wchar=wchar)
        self.state.history.add_call(('strlen', True, b_addr))
        maxlen = self.state.solver.BVV(max(a_strlen.max_null_index, b_strlen.max_null_index), self.state.arch.bits)

        strncmp = self.inline_call(angr.SIM_PROCEDURES['libc']['strncmp'], a_addr, b_addr, maxlen, a_len=a_strlen, b_len=b_strlen, wchar=wchar, ignore_case=ignore_case, nested_call = True)
        return strncmp.ret_expr
