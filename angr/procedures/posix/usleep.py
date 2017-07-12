import angr
from angr.sim_type import SimTypeInt
import logging

l = logging.getLogger("angr.procedures.posix.usleep")


class usleep(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, n): #pylint:disable=unused-argument
        self.argument_types = {0: SimTypeInt(32, False)}
        self.return_type = SimTypeInt(32, True)
        return 0
