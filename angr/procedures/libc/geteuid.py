import angr

######################################
# geteuid
######################################


class geteuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
