import logging
import claripy

from ..java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class SystemCurrentTimeMillis(JavaSimProcedure):
    __provides__ = (("java.lang.System", "currentTimeMillis()"),)

    def run(self):
        log.debug("Called SimProcedure java.lang.System.currentTimeMillis with args")

        from time import time

        return claripy.BVV(int(time() * 1000), 64)
