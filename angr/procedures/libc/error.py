import angr

from .exit import exit

######################################
# error
######################################

class error(exit):

    def run(self, status, errnum, fmtstr, *args, **kwargs):

        # TODO: output error message
        status_c = self.state.solver.eval(status)
        if status_c != 0:
            self._run_exit_handlers()
