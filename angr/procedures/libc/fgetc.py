import angr
from angr.sim_type import SimTypeInt

from . import io_file_data_for_arch

######################################
# fgetc
######################################


class fgetc(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, file_ptr):
        self.return_type = SimTypeInt(32, True)

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset : ].int.resolved

        data = self.inline_call(
            angr.SIM_PROCEDURES['libc.so.6']['_IO_getc'], fd).ret_expr
        return data
