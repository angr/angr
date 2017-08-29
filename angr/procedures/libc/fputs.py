import angr

from . import io_file_data_for_arch

######################################
# fputs
######################################

class fputs(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, str_addr, file_ptr):
        # TODO handle errors
        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fileno = self.state.mem[file_ptr + fd_offset:].int.resolved

        strlen = angr.SIM_PROCEDURES['libc']['strlen']
        p_strlen = self.inline_call(strlen, str_addr)
        str_expr = self.state.memory.load(str_addr, p_strlen.max_null_index, endness='Iend_BE')
        str_val = self.state.se.eval(str_expr, cast_to=str)

        self.state.posix.write(fileno, str_val, p_strlen.max_null_index)

        return 1
