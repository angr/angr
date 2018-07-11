from . import SimIRStmt

class SimIRStmt_insn_start(SimIRStmt):
    def _execute(self):
        self.state.history.recent_instruction_count += 1
