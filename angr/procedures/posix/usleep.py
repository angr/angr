import angr
from angr.sim_type import SimTypeInt
import logging

l = logging.getLogger(name=__name__)


class usleep(angr.SimProcedure):
    #pylint:disable=arguments-differ

    def run(self, n): #pylint:disable=unused-argument
        return 0
