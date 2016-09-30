class SimLLInsn(object):
    def __init__(self, bb, insn_idx, addr, state):
        self.addr = addr
        self.insn_idx = insn_idx
        self.state = state
        self.result = None

        # temporarily store this
        self.insn = bb.instructions[insn_idx]
        self.bb = bb

        # references by the statement
        self.actions = []
        self._constraints = []

    def process(self):
        self._execute()

        if self.insn.type != 'void':
            slot = self.insn._bb.tracker.lookup_local(self.insn._bb._func, self.insn)
            self.state.mem.store(slot, self.result)

        del self.insn
        del self.bb

    def _execute(self):
        raise NotImplementedError()

    def _fetch_expr(self, expr):
        slot = self.insn._bb.tracker.lookup_local(self.insn._bb._func, expr)
        return self.state.mem.load(slot)

    def _fetch_operand(self, op_idx):
        return self._fetch_expr(self.insn.operands[op_idx])
