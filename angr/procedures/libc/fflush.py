from __future__ import annotations
import angr

import logging

l = logging.getLogger(name=__name__)


class fflush(angr.SimProcedure):
    # pylint:disable=arguments-differ,unused-argument

    def run(self, fd):
        return 0


fflush_unlocked = fflush
