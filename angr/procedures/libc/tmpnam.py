import angr
import tempfile

######################################
# tmpnam
######################################

class tmpnam(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, tmp_file_path_addr):
        L_tmpnam = 20

        if self.state.se.eval(tmp_file_path_addr) != 0:
            return tmp_file_path_addr

        tmp_file_path = tempfile.mktemp()
        malloc = angr.SIM_PROCEDURES['libc']['malloc']
        addr = self.inline_call(malloc, L_tmpnam).ret_expr
        self.state.memory.store(addr,
                                tmp_file_path + '\x00')

        return addr
