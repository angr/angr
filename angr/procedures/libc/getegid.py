import angr
from angr.sim_type import SimTypeInt

######################################
# getegid
######################################


class getegid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        return 1000
