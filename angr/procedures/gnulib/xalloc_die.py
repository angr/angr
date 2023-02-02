import angr

######################################
# xalloc_die
######################################


class xalloc_die(angr.SimProcedure):
    """
    xalloc_die
    """

    NO_RET = True

    # pylint: disable=arguments-differ
    def run(self):
        self.exit(1)
