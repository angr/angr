import angr

######################################
# open
######################################

class open(angr.SimProcedure): #pylint:disable=W0622
    #pylint:disable=arguments-differ

    IS_SYSCALL = True

    def run(self, path, flags):
        fd = self.state.posix.open(path, flags)
        if fd is None:
            return -1
        return fd
