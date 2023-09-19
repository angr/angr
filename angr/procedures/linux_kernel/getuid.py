import angr
from angr.sim_type import SimTypeInt


class getuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(16, True)
        return 1000


class getuid32(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self):
        self.return_type = SimTypeInt(32, True)
        return 1000
