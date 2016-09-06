from .base import SimIRExpr

import logging
l = logging.getLogger('simuvex.vex.expressions.vecret')

class SimIRExpr_VECRET(SimIRExpr):
    def _execute(self):
        l.warning("VECRET IRExpr encountered. This is (probably) not bad, but we have no real idea how to handle it.")
        self.type = "Ity_I32"
        self.expr = self.state.se.BVV("OMG!")

