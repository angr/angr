from ..ffi import LLVMOpcode

def _merge_dicts(*dicts):
    out = {}
    for d in dicts:
        out.update(d)
    return out

_OPCODE_MAP = _merge_dicts(
    {LLVMOpcode(i): SimLLBinOpInsn for i in xrange(LLVMOpcode.add.value, LLVMOpcode.xor.value + 1)},
    {LLVMOpcode.ret: SimLLRetInsn},
)

def translate_insn(bb, insn_idx, addr, state):
    insn = bb.instructions[insn_idx]

    if insn.opcode in _OPCODE_MAP:
        s_insn = _OPCODE_MAP[insn.opcode](bb, insn_idx, addr, state)
        s_insn.process()
        return s_insn
    else:
        raise UnsupportedLLVMInsnError("Unsupported instruction opcode %s" % insn.opcode)

from .binop import SimLLBinOp
from .ret import SimLLRetInsn
