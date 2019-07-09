
import logging

from ..values import SimSootValue_ThisRef
from .base import SimSootExpr

l = logging.getLogger('angr.engines.soot.expressions.new')


class SimSootExpr_New(SimSootExpr):
    def _execute(self):
        # get object class
        obj_class = self.state.javavm_classloader.get_class(class_name=self.expr.type,
                                                            init_class=True)
        # return object reference
        # => fields getting lazy initialized in the javavm memory
        self.expr = SimSootValue_ThisRef(heap_alloc_id=self.state.memory.get_new_uuid(),
                                         type_=obj_class.name)
