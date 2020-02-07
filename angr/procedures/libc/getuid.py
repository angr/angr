import angr
from angr.sim_type import SimTypeInt

######################################
# getuid
######################################


class getuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000