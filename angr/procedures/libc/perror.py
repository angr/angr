import angr

######################################
# perror
######################################

class perror(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        write = angr.SIM_PROCEDURES['posix']['write']
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
