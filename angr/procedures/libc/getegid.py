import angr


class getegid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
