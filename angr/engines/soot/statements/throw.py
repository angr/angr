from __future__ import annotations

import logging

from archinfo.arch_soot import SootAddressTerminator

from angr import claripy

from .base import SimSootStmt

l = logging.getLogger(name=__name__)


class SimSootStmt_Throw(SimSootStmt):
    def _execute(self):
        # TODO: implement simprocedure to throw exception
        self._add_jmp_target(target=SootAddressTerminator(), condition=claripy.true())
