
import logging

from archinfo import ArchSoot

from .base import SimSootExpr

l = logging.getLogger("angr.engines.soot.expressions.cast")


class SimSootExpr_Cast(SimSootExpr):
    def _execute(self):
        # get value
        local = self._translate_value(self.expr.value)
        value_uncasted = self.state.memory.load(local)
        # cast value
        if self.expr.cast_type in ArchSoot.primitive_types:
            javavm_simos = self.state.project.simos
            self.expr = javavm_simos.cast_primitive(value_uncasted, to_type=self.expr.cast_type)
        else:
            l.error('Unknown casting type %s', self.expr.cast_type)
