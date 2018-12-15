from .base import SimIRExpr


class SimIRExpr_GSPTR(SimIRExpr):

    __slots__ = []

    def _execute(self):
        self.type = "Ity_I%d" % self.state.arch.bits # wow, this is ugly
        self.expr = self.state.solver.BVV(0, self.state.arch.bits)
