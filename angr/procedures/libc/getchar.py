import angr
from angr.sim_type import SimTypeInt

######################################
# getchar
######################################


class getchar(angr.SimProcedure):

    def run(self):
        self.return_type = SimTypeInt(32, True)
        data = self.inline_call(
            angr.SIM_PROCEDURES['libc.so.6']['_IO_getc'], 0).ret_expr  # stdin
        return data
