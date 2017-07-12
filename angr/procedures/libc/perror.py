import angr

######################################
# perror
######################################

class perror(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        # TODO: use something that's not a linux syscall
        write = angr.SIM_PROCEDURES['linux_kernel']['write']
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
