from . import SimIRStmt


class SimIRStmt_NoOp(SimIRStmt):

    __slots__ = []

    def _execute(self):
        pass
