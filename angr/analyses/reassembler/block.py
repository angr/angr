import logging
from .instruction import Instruction
from .ramblr_utils import multi_ppc_build, multi_arm_build
l = logging.getLogger("angr.analyses.reassembler")

class BasicBlock(object):
    """
    BasicBlock represents a basic block in the binary.
    """
    def __init__(self, binary, addr, size):
        """
        Constructor.

        :param Reassembler binary: The Binary analysis.
        :param int addr: Address of the block
        :param int size: Size of the block
        :return: None
        """

        self.binary = binary
        self.project = binary.project

        self.addr = addr
        self.size = size

        self.instructions = [ ]

        self._initialize()

    #
    # Overridden predefined methods
    #

    def __str__(self):
        """
        Return a linear representation of all instructions in this block.
        :return:
        """

        return self.assembly(symbolized=False)

    def __repr__(self):

        return "<BasicBlock %#08x>" % self.addr

    #
    # Public methods
    #

    def assign_labels(self):
        for ins in self.instructions:
            ins.assign_labels()

    def assembly(self, comments=False, symbolized=True):
        l.warning("Deprecated call to block.assembly: change to assemble_block")
        return self.assemble_block(comments, symbolized)


    def assemble_block(self, comments=False, symbolized=True):
        return "\n".join([ins.assemble_insn(comments=comments, symbolized=symbolized) for ins in self.instructions])

    def instruction_addresses(self):
        return sorted([ (ins.addr, ins.size) for ins in self.instructions ], key=lambda x: x[0])

    #
    # Private methods
    #

    def _initialize(self):
        """

        :return:
        """

        # re-lifting
        block = self.project.factory.fresh_block(self.addr, self.size)
        capstone_obj = block.capstone

        # Fill in instructions
        for instr in capstone_obj.insns:
            instruction = Instruction(self.binary, instr.address, instr.size, None, instr)
            #l.debug("Initialized oprand {:x}\t{} {}".format(instr.address, instr.mnemonic, instr.op_str))

            self.instructions.append(instruction)

        self.instructions = sorted(self.instructions, key=lambda x: x.addr)
        self._find_extra_pointers()


    def _find_extra_pointers(self):
        """
        Check for loading a 32-bit value into a register through two instructions with 16-bit values

        If detected, compute the full-width value and check if it's a pointer and then update both operands
        to be CODE/DATAREFS and use the label with apperoate modifiers for the architecture (ppc is label@ha
        or label@l, arm is #:lower16:label and #upper16:label

        Can be run for all architectures, will return immediately if unnecessary/misisng-support

        This assumes that the two operations that are required to put a 32 bit value into a register would occur in the same basic block

        :return:
        """

        # for PPC
        # cur_ins msut be loading a constant into a register, e.g. lis r1 100
        # nxt_ins msut be adding a constant to that register, e.g., addi _, r1, 500

        # Hopefully the cur/next pairs are always in the same order
        arm = { "cur": ["movw"],
                "next": ["movt"],
                "build_fn": multi_arm_build,
                "low_prefix": "#:lower16:",
                "high_prefix": "#:upper16:",
                "low_suffix": None,
                "high_suffix": None,
                "operand_idx0": 0,
                "operand_idx1": 0
                }

        ppc = { "cur": ["lis"],
                "next": ["addi"],
                "build_fn": multi_ppc_build,
                "low_prefix": None,
                "high_prefix": None,
                "low_suffix": "@l",
                "high_suffix":"@ha",
                "operand_idx0": 1,
                "operand_idx1": 0
                }

        settings_map = {"ARMEL": arm,
                        "PPC32": ppc}

        if self.project.arch.name in settings_map.keys():
            settings = settings_map[self.project.arch.name]
        else:
            return

    #if nxt_insn.operands[0].operand_str.strip() != cur_insn.operands[0].operand_str.strip():
    #if nxt_insn.operands[1].operand_str.strip() != cur_insn.operands[0].operand_str.strip():

        # For each in settings["cur"], find the next instruction in settings["next"]
        # This lets us get past any unrelated instructions thrown in the middle
        # If another instruction WRITES to the same register, delete the label on cur_insn and return

        for idx in range(len(self.instructions)-1):
            cur_insn = self.instructions[idx]
            nxt_insn = None
            if cur_insn.mnemonic not in settings["cur"]:
                continue

            targ_register = cur_insn.operands[settings["operand_idx0"]].operand_str.strip()
            for idx2 in range(idx+1, len(self.instructions)):
                if self.instructions[idx2].mnemonic in settings["next"] and \
                    self.instructions[idx2].operands[settings["operand_idx1"]].operand_str.strip() == targ_register:
                    nxt_insn = self.instructions[idx2]
                    break
                elif len(self.instructions[idx2].operands) > settings["operand_idx0"] and \
                        self.instructions[idx2].operands[settings["operand_idx0"]].operand_str.strip() == targ_register:
                    # Cur insn couldn't be moving a label because it only did half a mov before something else clobbered that register
                    if self.instructions[idx2].addr - cur_insn.addr < 5:
                        # Seen warning once in real code and it was fine, it's just an immediate
                        l.warning("Odd assembly behavior with ignored value in %s", targ_register)
                    cur_insn.operands[1].label = None
                    return

            if not nxt_insn:
                # Explicitly make the half-width value as a constant
                if len(cur_insn.operands) > 1:
                    cur_insn.operands[1].label = None
                continue

            high_imm, low_imm, cur_op_imm, nxt_op_imm = settings["build_fn"](cur_insn, nxt_insn)

            if low_imm is None:
                continue

            full_addr = (high_imm<<16) + low_imm

            # Check if they form a valid code/data pointer
            nxt_op_imm.is_coderef, nxt_op_imm.is_dataref, \
                baseaddr = nxt_op_imm._imm_to_ptr(full_addr, nxt_op_imm.type, nxt_op_imm.mnemonic, self.project.arch.name)

            # If so, set the label offset's to be ha and l. TODO - may need logic for swapping order if that ever occurs
            if nxt_op_imm.is_dataref or nxt_op_imm.is_coderef: # TODO: is is_coderef gonna break things?
                cur_op_imm.label = cur_op_imm.binary.symbol_manager.new_label(addr=baseaddr)
                nxt_op_imm.label = nxt_op_imm.binary.symbol_manager.new_label(addr=baseaddr)

                cur_op_imm.label_suffix = settings["low_suffix"]
                nxt_op_imm.label_suffix = settings["high_suffix"]

                cur_op_imm.label_prefix = settings["low_prefix"]
                nxt_op_imm.label_prefix = settings["high_prefix"]
            else:
                # No labels, it's a constant in 2 registers
                cur_op_imm.label = None
                nxt_op_imm.label  = None

            # Don't call register_instruction_reference since we aren't actually jumping/calling the address yet. Hopefully that already happens elsewhere


