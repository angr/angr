
import logging

from archinfo import ArchSoot

from .base import SimSootExpr
from ..values.thisref import SimSootValue_ThisRef
from ..values.arrayref import SimSootValue_ArrayBaseRef

l = logging.getLogger("angr.engines.soot.expressions.cast")


class SimSootExpr_Cast(SimSootExpr):
    def _execute(self):
        # get value
        local = self._translate_value(self.expr.value)
        value_uncasted = self.state.memory.load(local)
        # cast value
        if self.expr.cast_type in ArchSoot.primitive_types:
            javavm_simos = self.state.project.simos
            self.expr = javavm_simos.cast_primitive(self.state,
                                                    value_uncasted,
                                                    to_type=self.expr.cast_type)
        # We are casting an array
        elif isinstance(value_uncasted, SimSootValue_ArrayBaseRef):
            self.expr = SimSootValue_ArrayBaseRef(value_uncasted.heap_alloc_id, self.expr.cast_type.replace('[]', ''),
                                                  value_uncasted.size)
        else:
            self.expr = SimSootValue_ThisRef(heap_alloc_id=value_uncasted.heap_alloc_id,
                                             type_=self.expr.cast_type)
