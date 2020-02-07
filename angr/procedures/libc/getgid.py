import angr
from angr.sim_type import SimTypeInt

######################################
# getgid
######################################


class getgid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000