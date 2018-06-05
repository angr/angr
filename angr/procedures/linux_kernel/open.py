import angr

from ..posix import open as xopen

######################################
# open
######################################

class open(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    # FIXME: weird args length different when direct using posix.open(path, flags)
    def run(self, path, flags, mode=0o644):
        ret_expr = self.inline_call(xopen.open, path, flags, mode).ret_expr
        return ret_expr
