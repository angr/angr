import angr
import claripy
import logging
from angr.errors import SimProcedureError

l = logging.getLogger(name=__name__)

class strncat(angr.SimProcedure):
    def run(self, dest, src, n):
        strncpy = angr.SIM_PROCEDURES['libc']['strncpy']
        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        dest_len = self.inline_call(strlen, dest).ret_expr
        src_len = self.inline_call(strlen, src).ret_expr
        self.inline_call(strncpy, dest + dest_len, src, n, src_len)
        return dest




