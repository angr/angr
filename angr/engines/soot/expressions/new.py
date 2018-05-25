
from .base import SimSootExpr
from ..values import SimSootValue_ThisRef

import logging

l = logging.getLogger('angr.engines.soot.expressions.new')


class SimSootExpr_New(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_New, self).__init__(expr, state)

    def _execute(self):
        try:
            # create just the reference to pass to the constructor method
            class_ = self.state.project.loader.main_bin.classes[self.expr.type]
            heap_allocation_id = self.state.memory.get_new_uuid()
            self.expr = SimSootValue_ThisRef(heap_allocation_id, class_.name)
        except KeyError:
            l.warning("Trying to create an object of a non loaded class %s", self.expr.type)


