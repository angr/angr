from __future__ import annotations

import logging

import claripy

from .base import SimSootExpr

l = logging.getLogger(name=__name__)


class SimSootExpr_InstanceOf(SimSootExpr):
    def _execute(self):
        obj = self._translate_value(self.expr.value)
        self.expr = claripy.StringV(obj.type) == claripy.StringV(self.expr.check_type)
