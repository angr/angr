import angr


class std__terminate(angr.SimProcedure):  # pylint:disable=redefined-builtin
    # pylint:disable=arguments-differ

    NO_RET = True
    ALT_NAMES = ("std::terminate()",)

    def run(self):
        # FIXME: Call terminate handlers
        self.exit(1)
