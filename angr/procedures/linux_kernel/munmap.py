import angr


class munmap(angr.SimProcedure):
    def run(self, addr, length):  # pylint:disable=arguments-differ,unused-argument
        # TODO: actually do something
        return 0
