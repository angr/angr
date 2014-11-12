import simuvex
from simuvex.s_type import SimTypeInt
import logging

l = logging.getLogger("simuvex.procedures.usleep")


class usleep(simuvex.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, n): #pylint:disable=unused-argument
        self.argument_types = {0: SimTypeInt(32, False)}
        self.return_type = SimTypeInt(32, True)
        self.ret()
