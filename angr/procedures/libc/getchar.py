import angr
from angr.sim_type import SimTypeInt

######################################
# getchar
######################################


class getchar(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(32, True)
        fgetc = angr.SIM_PROCEDURES['libc']['fgetc']
        stdin = self.state.posix.get_fd(0)
        data = self.inline_call(fgetc, 0, simfd=stdin).ret_expr
        return data
