import capstone

#
# Constants
#

OP_TYPE_REG = 1
OP_TYPE_IMM = 2
OP_TYPE_MEM = 3
OP_TYPE_OTHER = 4

OP_TYPE_MAP = {
    OP_TYPE_REG: 'REG',
    OP_TYPE_IMM: 'IMM',
    OP_TYPE_MEM: 'MEM',
    OP_TYPE_OTHER: 'OTHER',
}

CAPSTONE_OP_TYPE_MAP = {
    'X86': {
        capstone.x86.X86_OP_REG: OP_TYPE_REG,
        capstone.x86.X86_OP_IMM: OP_TYPE_IMM,
        capstone.x86.X86_OP_MEM: OP_TYPE_MEM,
    },
    'MIPS32': {
        capstone.mips.MIPS_OP_REG: OP_TYPE_REG,
        capstone.mips.MIPS_OP_IMM: OP_TYPE_IMM,
        capstone.mips.MIPS_OP_MEM: OP_TYPE_MEM,
    },
    'AMD64': {
        capstone.x86.X86_OP_REG: OP_TYPE_REG,
        capstone.x86.X86_OP_IMM: OP_TYPE_IMM,
        capstone.x86.X86_OP_MEM: OP_TYPE_MEM,
    },
    'PPC32': {
        capstone.ppc.PPC_OP_REG: OP_TYPE_REG,
        capstone.ppc.PPC_OP_IMM: OP_TYPE_IMM,
        capstone.ppc.PPC_OP_MEM: OP_TYPE_MEM,
    },
    'PPC64': {
        capstone.ppc.PPC_OP_REG: OP_TYPE_REG,
        capstone.ppc.PPC_OP_IMM: OP_TYPE_IMM,
        capstone.ppc.PPC_OP_MEM: OP_TYPE_MEM,
    },
    'ARMEL': {
        capstone.arm.ARM_OP_REG: OP_TYPE_REG,
        capstone.arm.ARM_OP_IMM: OP_TYPE_IMM,
        capstone.arm.ARM_OP_MEM: OP_TYPE_MEM,
        capstone.arm.ARM_OP_SYSREG: OP_TYPE_OTHER,
        capstone.arm.ARM_OP_SETEND: OP_TYPE_OTHER,
        capstone.arm.ARM_OP_PIMM: OP_TYPE_OTHER,
    },
}


# Create and fill CAPSTONE_REG_MAP
CAPSTONE_REG_MAP = {}
for arch_name in CAPSTONE_OP_TYPE_MAP.keys():
    CAPSTONE_REG_MAP[arch_name] = {}

# TODO: Support more architectures
for attr in dir(capstone.x86):
    if attr.startswith('X86_REG_'):
        reg_name = attr[8:]
        reg_offset = getattr(capstone.x86, attr)
        CAPSTONE_REG_MAP['X86'][reg_offset] = reg_name.lower()

for attr in dir(capstone.x86):
    if attr.startswith('X86_REG_'):
        reg_name = attr[8:]
        reg_offset = getattr(capstone.x86, attr)
        CAPSTONE_REG_MAP['AMD64'][reg_offset] = reg_name.lower()

for attr in dir(capstone.ppc):
    if attr.startswith('PPC_REG_'):
        reg_name = attr[8:]
        reg_offset = getattr(capstone.ppc, attr)
        CAPSTONE_REG_MAP['PPC32'][reg_offset] = reg_name.lower()

for attr in dir(capstone.arm):
    if attr.startswith('ARM_REG_'):
        reg_name = attr[8:]
        reg_offset = getattr(capstone.arm, attr)
        CAPSTONE_REG_MAP['ARMEL'][reg_offset] = reg_name.lower()


# Utility functions
def string_escape(s):
    s = s.encode('string_escape')
    s = s.replace("\\'", "'")
    s = s.replace("\"", "\\\"")

    return s

def split_operands(s):
    operands = [ ]
    operand = ""
    in_paranthesis = False
    for i, c in enumerate(s):
        if in_paranthesis and c == ")":
            in_paranthesis = False
        if c == "(":
            in_paranthesis = True
        if not in_paranthesis and c == "," and (i == len(s) - 1 or s[i + 1] == ' '):
            operands.append(operand)
            operand = ""
            continue
        operand += c

    if operand:
        operands.append(operand)

    return operands

def is_hex(s):
    try:
        int(s, 16)
        return True
    except ValueError:
        return False

def ignore_function(proc):
    # Examine calls from function, if any are blacklisted, return true to keep this entire function
    # from being included in disassembly

    bad_fns = ["deregister_tm_clones", "__gmon_start__"]

    for b in sorted(proc.blocks, key=lambda x:x.addr):  # type: BasicBlock
        s = b.assemble_block(comments=False, symbolized=True)
        for bad in bad_fns:
            if bad in s:
                return True

    return False

def multi_ppc_build(cur_insn, nxt_insn):
    """
    For PPC we build a multi-instruction address when we see
        mov reg0 const0
        add reg1 reg0 const1

        so that our label is at (const0<<16)+const1, we want to set reg1 to be that label
    """
    if len(cur_insn.operands) != 2 or len(nxt_insn.operands) != 3:
        return [None]*4

    #Make sure we're using the same register
    if nxt_insn.operands[1].operand_str.strip() != cur_insn.operands[0].operand_str.strip():
        return [None]*4
    # The operands that (when combined) point to full_addr

    def op_to_int(op, off):
        return int(op.operands[off].operand_str, 16)

    high = op_to_int(cur_insn, 1)
    low = op_to_int(nxt_insn, 2)
    return [high, low, cur_insn.operands[1], nxt_insn.operands[2]]

def multi_arm_build(cur_insn, nxt_insn):
    """
    for arm we build a multi-instruction address when we see
        movw reg0 const0
        ...
        movt reg0 const1

        so that our label is at (const0<<16)+const1 and we want to set reg0 to that label
    """

    # make sure we're using the same register
    if nxt_insn.operands[0].operand_str.strip() != cur_insn.operands[0].operand_str.strip():
        return [None]*4

    def op_to_int(op, off):
        imm = op.operands[off].operand_str.split("#")[1]
        if imm.startswith("0x"):
            imm = imm[2:]
        return int(imm, 16)

    high = op_to_int(nxt_insn, 1)
    low = op_to_int(cur_insn, 1)
    return [high, low, cur_insn.operands[1], nxt_insn.operands[1]]

