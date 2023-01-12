import angr

######################################
# putchar
######################################


class putchar(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, string):
        stdout = self.state.posix.get_fd(1)
        if stdout is None:
            return -1
        stdout.write_data(string[7:0])
        return string & 0xFF
