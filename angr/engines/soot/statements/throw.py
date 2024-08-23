from __future__ import annotations
import logging

import claripy
from archinfo.arch_soot import SootAddressTerminator

from .base import SimSootStmt

l = logging.getLogger(name=__name__)


class SimSootStmt_Throw(SimSootStmt):
    def _execute(self):
        # TODO: implement simprocedure to throw exception
        self._add_jmp_target(target=SootAddressTerminator(), condition=claripy.true)
