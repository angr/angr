from ....s_run import SimRun

class SimLLVMBasicBlock(SimRun):
    def __init__(self, state, bb, **kwargs):
        super(SimLLVMBasicBlock, self).__init__(self, state, **kwargs)

        self.bb = bb

        try:
            self._handle_bb()
        except SimError as e:
            e.record_state(self.state)
            raise

    def _handle_bb(self):
        self._handle_instructions()

    def _handle_instructions():
        for insn_idx, insn in enumerate(self.bb.instructions):
            
