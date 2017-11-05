
import capstone as cs

def decode_instruction(arch, instr):
    # this is clearly architecture specific

    INS_GROUP_INFO = {
        'X86': {
            cs.x86.X86_GRP_CALL: 'call',
            cs.x86.X86_GRP_JUMP: 'branch',
            cs.x86.X86_GRP_RET: 'return',
        },
        'AMD64': {
            cs.x86.X86_GRP_CALL: 'call',
            cs.x86.X86_GRP_JUMP: 'branch',
            cs.x86.X86_GRP_RET: 'return',
        },
        'MIPS32': {
            cs.mips.MIPS_GRP_CALL: 'call',
            cs.mips.MIPS_GRP_JUMP: 'branch',
            cs.mips.MIPS_GRP_RET: 'return',
        }
    }

    INS_INFO = {
        'MIPS32': {
            cs.mips.MIPS_INS_JAL: 'call',
            cs.mips.MIPS_INS_BAL: 'branch',
        }
    }

    arch_name = arch.name

    insn_info = None

    info = INS_GROUP_INFO.get(arch_name, None)
    if info is not None:
        for group in instr.insn.insn.groups:
            insn_info = info.get(group, None)
            if insn_info is not None:
                break

    if insn_info is None:
        info = INS_INFO.get(arch_name, None)
        if info is not None:
            insn_info = info.get(instr.insn.insn.id, None)

    if insn_info is None:
        return

    instr.type = insn_info

    if instr.type in ('call', 'branch'):
        # determine if this is a direct or indirect call/branch
        if arch_name in ('X86', 'AMD64'):
            last_operand = instr.insn.operands[-1]
            if last_operand.type == cs.x86.X86_OP_IMM:
                instr.branch_type = 'direct'
            else:
                instr.branch_type = 'indirect'
            instr.branch_target_operand = len(instr.insn.operands) - 1

        elif arch_name == 'MIPS32':
            # check the last operand
            last_operand = instr.insn.operands[-1]
            if last_operand.type == cs.mips.MIPS_OP_REG:
                instr.branch_type = 'indirect'
            else:
                instr.branch_type = 'direct'
            instr.branch_target_operand = len(instr.insn.operands) - 1
