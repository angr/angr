import angr


class UnresolvableCallTarget(angr.SimProcedure):
    NO_RET = False

    def run(self):  # pylint: disable=arguments-differ
        return
