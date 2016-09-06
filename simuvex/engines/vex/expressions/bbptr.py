from .base import SimIRExpr

class SimIRExpr_BBPTR(SimIRExpr):
    def _execute(self):
        self.type = "Ity_I%d" % self.state.arch.bits # wow, this is ugly
        self.expr = self.state.se.BVV(0, self.state.arch.bits)
