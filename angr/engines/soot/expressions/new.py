
from .base import SimSootExpr
from ..values import SimSootValue_ThisRef

import logging

l = logging.getLogger('angr.engines.soot.expressions.new')


class SimSootExpr_New(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_New, self).__init__(expr, state)

    def _execute(self):

        try:
            class_ = self.state.project.loader.main_bin.classes[self.expr.type]
            obj = SimSootValue_ThisRef(self.state.ip.method.fullname)
            self.state.memory.store()
        except KeyError:
            l.warning("Trying to create an object of a non loaded class %s", self.expr.type)


