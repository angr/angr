import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch
from ...errors import SimSolverError

######################################
# fseek
######################################

class fseek(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr, offset, whence):
        # TODO: Support symbolic file_ptr, offset, and whence

        # Make sure whence can only be one of the three values: SEEK_SET(0), SEEK_CUR(1), and SEEK_END(2)
        try:
            whence = self.state.solver.eval_one(whence)
        except SimSolverError:
            raise angr.SimProcedureError('multi-valued "whence" is not supported in fseek.')

        try:
            whence = {0: 'start', 1: 'current', 2: 'end'}[whence]
        except KeyError:
            return -1 # EINVAL

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset].int.resolved
        simfd = self.state.posix.get_fd(fd)
        if simfd is None:
            return -1
        return self.state.solver.If(simfd.seek(offset, whence), self.state.solver.BVV(0, self.state.arch.bits), -1)
