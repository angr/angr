import angr
import claripy
import logging
from angr.errors import SimProcedureError

l = logging.getLogger(name=__name__)

# note: this does not handle skipping white space

class strtoul(angr.SimProcedure):
    #pylint:disable=arguments-differ
    def run(self, nptr, endptr, base):
        strtol = angr.SIM_PROCEDURES['libc']['strtol']
        return self.inline_call(strol, nptr, endptr, base)
        