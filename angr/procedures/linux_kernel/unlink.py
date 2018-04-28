import angr

######################################
# unlink
######################################

class unlink(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, path_addr):
        # This is a dummy for now
        strlen = angr.SIM_PROCEDURES['libc']['strlen']

        p_strlen = self.inline_call(strlen, path_addr)
        str_expr = self.state.memory.load(path_addr, p_strlen.max_null_index, endness='Iend_BE')
        str_val = self.state.se.eval(str_expr, cast_to=str)

        if self.state.fs.delete(str_val):
            return 0
        else:
            return -1
