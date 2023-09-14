import angr


class xstrtol_fatal(angr.SimProcedure):
    """
    xstrtol_fatal
    """

    NO_RET = True

    # pylint: disable=unused-argument,arguments-differ
    def run(self, err, opt_idx, c, long_options, arg):
        self.exit(1)
