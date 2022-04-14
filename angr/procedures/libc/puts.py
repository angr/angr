import angr

######################################
# puts
######################################

class puts(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, string):

        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        length = self.inline_call(strlen, string).ret_expr
        out = stdout.write(string, length)
        stdout.write_data(self.state.solver.BVV(b'\n'))
        return (out + 1)[31:0]
