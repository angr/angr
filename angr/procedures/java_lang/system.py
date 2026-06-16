from __future__ import annotations

import logging
from time import time

import claripy

from angr.procedures.java import JavaSimProcedure

log = logging.getLogger(name=__name__)


class SystemCurrentTimeMillis(JavaSimProcedure):
    __provides__ = (("java.lang.System", "currentTimeMillis()"),)

    def run(self):
        log.debug("Called SimProcedure java.lang.System.currentTimeMillis with args")

        return claripy.BVV(int(time() * 1000), 64)
