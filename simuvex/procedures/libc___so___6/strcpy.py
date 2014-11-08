import simuvex
from simuvex.s_type import SimTypeString

class strcpy(simuvex.SimProcedure):
    def analyze(self):
        self.argument_types = {0: self.ty_ptr(SimTypeString()),
                               1: self.ty_ptr(SimTypeString())}
        self.return_type = self.ty_ptr(SimTypeString())

        strlen = simuvex.SimProcedures['libc.so.6']['strlen']
        strncpy = simuvex.SimProcedures['libc.so.6']['strncpy']

        dst = self.arg(0)
        src = self.arg(1)
        src_len = self.inline_call(strlen, src)

        ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len).ret_expr
        return ret_expr

