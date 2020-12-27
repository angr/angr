import angr

from cle.backends.externs.simdata.io_file import io_file_data_for_arch


######################################
# fileno
######################################

class fileno(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, f):
        # Get FILE struct
        io_file_data = io_file_data_for_arch(self.state.arch)

        # Get the file descriptor from FILE struct
        result = self.state.mem[f + io_file_data['fd']].int.resolved
        return result.sign_extend(self.arch.bits - len(result))

fileno_unlocked = fileno
