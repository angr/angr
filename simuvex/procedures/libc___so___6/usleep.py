import simuvex
from simuvex.s_type import SimTypeInt
import logging

l = logging.getLogger("simuvex.procedures.usleep")


class usleep(simuvex.SimProcedure):
    def __init__(self):  # pylint: disable=W0231,
        self.argument_types = {0: SimTypeInt(32, False)}
        self.return_type = SimTypeInt(32, True)
        self.ret()
