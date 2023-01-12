import angr
from .open import open


class opendir(angr.SimProcedure):
    def run(self, fname):
        p_open = self.inline_call(open, fname, 0o200000, 0)  # O_DIRECTORY
        # using the same hack we used to use for fopen etc... using the fd as a pointer
        return p_open.ret_expr
