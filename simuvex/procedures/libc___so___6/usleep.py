import simuvex
import logging

l = logging.getLogger("simuvex.procedures.usleep")


class usleep(simuvex.SimProcedure):
    def __init__(self):  # pylint: disable=W0231,
        retn_addr = self.exit_return()

