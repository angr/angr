from . import SimIRStmt

class SimIRStmt_IMark(SimIRStmt):
    def _execute(self):
        self.state.history.recent_instruction_count += 1
