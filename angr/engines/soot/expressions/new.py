
from .base import SimSootExpr

import logging

l = logging.getLogger('angr.engines.soot.expressions')


class SimSootExpr_New(SimSootExpr):
    def __init__(self, expr, state):
        super(SimSootExpr_New, self).__init__(expr, state)

    def _execute(self):

        try:
            class_ = self.state.project.loader.main_bin.classes[self.expr.type]
            obj = {}
        except KeyError:
            l.warning("Try to create an object of a non loaded class %s", self.expr.type)


