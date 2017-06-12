import simuvex

from . import io_file_data_for_arch

######################################
# fseek
######################################

class fseek(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, file_ptr, offset, whence):
        # TODO: Support symbolic file_ptr, offset, and whence

        # Make sure whence can only be one of the three values: SEEK_SET(0), SEEK_CUR(1), and SEEK_END(2)
        if self.state.se.symbolic(whence) and len(self.state.se.any_n_int(whence, 2)) > 1:
            raise simuvex.SimProcedureError('multi-valued "whence" is not supported in fseek.')
        else:
            # Get all possible values
            all_whence = self.state.se.any_n_int(whence, 2)
            if not all_whence:
                raise simuvex.SimProcedureError('"whence" has no satisfiable value.')

            # There is only one value left
            whence_int = all_whence[0]
            if whence_int not in (0, 1, 2):
                return 22 # EINVAL

        fd_offset = io_file_data_for_arch(self.state.arch)['fd']
        fd = self.state.mem[file_ptr + fd_offset : ].int.resolved
        r = self.state.posix.seek(fd, offset, whence_int)

        return r
