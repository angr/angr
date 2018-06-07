
from .base import SimSootExpr

from archinfo import ArchSoot

import logging
l = logging.getLogger("angr.engines.soot.expressions.cast")

class SimSootExpr_Cast(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Cast, self).__init__(expr, state)

    def _execute(self):

        if not self.expr.cast_type in ArchSoot.primitive_types:
            l.error('Casting of non-primitive types is not implemented.') 
            return

        if self.expr.cast_type in ['double', 'float']:
            l.error('Casting of double and float types is not implemented.')
            return
        
        local = self._translate_value(self.expr.value)
        value_uncasted = self.state.memory.load(local)
        value = self.state.project.simos.cast_primitive(value=value_uncasted,
                                                        to_type=self.expr.cast_type)
        self.expr = value
