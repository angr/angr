
import logging

from .base import SimSootStmt

l = logging.getLogger('angr.engines.soot.statements.if')


class SimSootStmt_If(SimSootStmt):
    def _execute(self):
        jmp_condition = self._translate_expr(self.stmt.condition).expr
        jmp_target = self._get_bb_addr_from_instr(instr=self.stmt.target)
        self._add_jmp_target(target=jmp_target,
                             condition=jmp_condition)
        self._add_jmp_target(target=None, # if target is None, engine goes on linearly
                             condition=(jmp_condition == self.state.solver.false))
