from . import SimIRStmt

class SimIRStmt_NoOp(SimIRStmt):
    def _execute(self):
        pass
