from __future__ import annotations
import logging

import claripy

from .base import SimSootStmt

l = logging.getLogger("angr.engines.soot.statements.goto")


class SimSootStmt_Goto(SimSootStmt):
    def _execute(self):
        jmp_target = self._get_bb_addr_from_instr(instr=self.stmt.target)
        self._add_jmp_target(target=jmp_target, condition=claripy.true)
