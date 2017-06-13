import angr

######################################
# perror
######################################

class perror(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        write = angr.SimProcedures['syscalls']['write']
        strlen = angr.SimProcedures['libc.so.6']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
