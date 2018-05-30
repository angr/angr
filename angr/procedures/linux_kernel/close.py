import angr

######################################
# close
######################################

class close(angr.SimProcedure):
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, fd):
        if self.state.posix.close(fd):
            return 0
        else:
            return -1
