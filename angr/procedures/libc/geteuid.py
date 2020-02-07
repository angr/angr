import angr
from angr.sim_type import SimTypeInt

######################################
# geteuid
######################################


class geteuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
