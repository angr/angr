import angr


class close(angr.SimProcedure):
    def run(self, fd):  # pylint:disable=arguments-differ
        if self.state.posix.close(fd):
            return 0
        else:
            return -1
