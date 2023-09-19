import angr


class realloc(angr.SimProcedure):
    # pylint:disable=arguments-differ
    def run(self, ptr, size):
        return self.state.heap._realloc(ptr, size)
