from .base import SimIRExpr

import logging
l = logging.getLogger(name=__name__)


class SimIRExpr_VECRET(SimIRExpr):

    __slots__ = []

    def _execute(self):
        l.warning("VECRET IRExpr encountered. This is (probably) not bad, but we have no real idea how to handle it.")
        self.type = "Ity_I32"
        self.expr = self.state.solver.BVV("OMG!")
