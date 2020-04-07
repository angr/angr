import angr

class strcat(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, dst, src):
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
        src_len = self.inline_call(strlen, src).ret_expr
        dst_len = self.inline_call(strlen, dst).ret_expr

        self.inline_call(strncpy, dst + dst_len, src, src_len+1, src_len=src_len)
        return dst
