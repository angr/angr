import claripy
import logging

from ..java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class Random(JavaSimProcedure):
    __provides__ = (("java.lang.Math", "random"),)

    def run(self):
        log.debug("Called SimProcedure java.lang.Math.random with args")
        return claripy.FPS("rand_int", claripy.FSORT_DOUBLE)
