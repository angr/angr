from __future__ import annotations
import logging

from .base import SimSootStmt

l = logging.getLogger("angr.engines.soot.statements.identity")


class SimSootStmt_Identity(SimSootStmt):
    def _execute(self):
        dst = self._translate_value(self.stmt.left_op)
        src_expr = self._translate_expr(self.stmt.right_op)
        src_val = src_expr.expr
        l.debug("Identity %s := %s", dst, src_val)
        self.state.memory.store(dst, src_val)
