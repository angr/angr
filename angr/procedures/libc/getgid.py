import angr
from angr.sim_type import SimTypeInt

######################################
# getgid
######################################


class getgid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(32, True)
        return 1000