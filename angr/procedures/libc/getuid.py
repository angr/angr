import angr

######################################
# getuid
######################################

class getuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
