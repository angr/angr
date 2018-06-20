
from .base import SimSootExpr
from ..values import SimSootValue_ThisRef

import logging
l = logging.getLogger('angr.engines.soot.expressions.new')

class SimSootExpr_New(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_New, self).__init__(expr, state)

    def _execute(self):
        # get object class
        obj_class = self.state.javavm_classloader.get_class(self.expr.type)
        if obj_class is None:
            l.warning("Trying to create an object of a non loaded class %s", self.expr.type)
            return
        # make sure class is loaded
        self.state.javavm_classloader.load_class(obj_class)
        # create object
        # Note: fields are initialized/created on first access (see instancefieldref/memory)
        self.expr = SimSootValue_ThisRef(heap_alloc_id=self.state.memory.get_new_uuid(),
                                         type_=self.expr.type)
