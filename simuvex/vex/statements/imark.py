from . import SimIRStmt

class SimIRStmt_IMark(SimIRStmt):
    def _execute(self):
        self.state.scratch.executed_instruction_count += 1
