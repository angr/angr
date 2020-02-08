import angr

class strcpy(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, dst, src):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
        src_len = self.inline_call(strlen, src)

        ret_expr = self.inline_call(strncpy, dst, src, src_len.ret_expr+1, src_len=src_len.ret_expr).ret_expr
        return ret_expr
