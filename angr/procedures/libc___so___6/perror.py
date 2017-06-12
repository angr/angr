import simuvex

######################################
# perror
######################################

class perror(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):
        write = simuvex.SimProcedures['syscalls']['write']
        strlen = simuvex.SimProcedures['libc.so.6']['strlen']

        length = self.inline_call(strlen, string).ret_expr
        self.inline_call(write, 2, string, length)
