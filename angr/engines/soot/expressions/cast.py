
from .base import SimSootExpr

from archinfo import ArchSoot

import logging
l = logging.getLogger("angr.engines.soot.expressions.cast")

class SimSootExpr_Cast(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_Cast, self).__init__(expr, state)

    def _execute(self):

        if self.expr.cast_type in ['double', 'float']:
            l.error('Casting of double and float types not supported.')
            return
        
        # get value
        local = self._translate_value(self.expr.value)
        value_uncasted = self.state.memory.load(local)

        # lookup the type size and extract value
        value_size = ArchSoot.sizeof[self.expr.cast_type] 
        value_extracted = value_uncasted.reversed.get_bytes(index=0, size=value_size/8).reversed

        # determine size of Soot bitvector and resize bitvector
        # Note: smaller types than int's are stored in a 32-bit BV 
        value_soot_size = value_size if value_size >= 32 else 32
        if self.expr.cast_type in ['char', 'boolean']:
            # unsigned extend
            value_casted = value_extracted.zero_extend(value_soot_size-value_size)
        else:
            # signed extend
            value_casted = value_extracted.sign_extend(value_soot_size-value_size)

        self.expr = value_casted
