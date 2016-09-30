from .insn import SimLLInsn


class SimLLBinOpInsn(SimLLBaseInsn):
    def __init__(self, bb, insn_idx, addr, state):
        super(SimLLBinOpInsn, self).__init__(bb, insn_idx, addr, state)

    def _execute(self):
        first, second = self._fetch_operand(0), self._fetch_operand(1)

        if self.insn.opcode in (LLVMOpcode.add, LLVMOpcode.f_add):
            self.result = first + second

from ..ffi import LLVMOpcode
