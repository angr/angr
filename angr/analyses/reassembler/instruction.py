import logging
from capstone import CS_OP_IMM
from .ramblr_utils import split_operands, OP_TYPE_IMM, OP_TYPE_MEM
from .ramblr_errors import BinaryError, InstructionError, ReassemblerFailureNotice
from .operand import Operand
l = logging.getLogger("angr.analyses.reassembler")

class Instruction(object):
    """
    High-level representation of an instruction in the binary
    """
    def __init__(self, binary, addr, size, insn_bytes, capstone_instr):
        """

        :param Reassembler binary: The Binary analysis
        :param int addr: Address of the instruction
        :param int size: Size of the instruction
        :param str insn_bytes: Instruction bytes
        :param capstone_instr: Capstone Instr object.
        :return: None
        """

        self.binary = binary
        self.project = binary.project
        self.addr = addr
        self.size = size
        self.bytes = insn_bytes

        self.mnemonic = capstone_instr.mnemonic

        self.op_str = capstone_instr.op_str
        self.capstone_operand_types = [ operand.type for operand in capstone_instr.operands ]

        self.operands = [ ]

        self.labels = [ ]

        if self.addr is not None:
            #l.debug("Initialize operand {:x}\t{} {}".format(addr, capstone_instr.mnemonic, capstone_instr.op_str))
            self._initialize(capstone_instr.operands)

    #
    # Overridden predefined instructions
    #
    def __str__(self):
        """

        :return:
        """

        assembly = self.assemble_insn(comments=True, symbolized=False)
        return assembly

    #
    # Public methods
    #

    def assign_labels(self):

        if self.addr in self.binary.symbol_manager.addr_to_label:
            labels = self.binary.symbol_manager.addr_to_label[self.addr]
            for label in labels:
                if label not in self.labels:
                    self.labels.append(label)

    def dbg_comments(self):
        operands = ", ".join([ str(operand) for operand in self.operands ])
        capstone_str = "%#08x:\t%s\t%s" % (self.addr, self.mnemonic, self.op_str)
        comments = "\t# %s [%s]" % (capstone_str, operands)

        return comments

    def assembly(self, comments=False, symbolized=True):
        l.warning("Deprecated call to instruction.assembly: change to assemble_insn")
        return self.assemble_insn(comments, symbolized)

    def assemble_insn(self, comments=False, symbolized=True):
        """

        :return:
        """

        if comments:
            dbg_comments = self.dbg_comments()
        else:
            dbg_comments = ""

        labels = "\n".join([ str(lbl) for lbl in self.labels ])

        inserted_asm_before_label = ""
        if self.addr in self.binary.inserted_asm_before_label:
            # put all assembly code there
            if comments:
                inserted_asm_before_label += "\t# Inserted assembly code (before label):\n"
            inserted_asm_before_label = "\n".join(self.binary.inserted_asm_before_label[self.addr])
            inserted_asm_before_label += "\n"

        inserted_asm_after_label = ""
        if self.addr in self.binary.inserted_asm_after_label:
            # put all assembly code there
            if comments:
                inserted_asm_after_label += "\t# Inserted assembly code (after label):\n"
            inserted_asm_after_label = "\n".join(self.binary.inserted_asm_after_label[self.addr])
            inserted_asm_after_label += "\n"

        not_symbolized = "\t%s\t%s" % (self.mnemonic, self.op_str)
        if not symbolized:
            asm = not_symbolized

        elif not any([ operand.symbolized for operand in self.operands ]):
            # No label is involved
            asm = not_symbolized

        elif not self.operands:
            # There is no operand
            asm = not_symbolized

        else:
            # Now it's the tricky part. capstone doesn't give us anyway to print individual operand. We gotta parse it
            # by ourselves
            # Remove the address
            #capstone_str = capstone_str[capstone_str.find('\t') + 1 : ]

            all_operands = [ operand.operand_str for operand in self.operands]
            mnemonic = self.mnemonic

            for i, op in enumerate(self.operands):
                op_asm = op.assembly()
                if op_asm is not None:
                    if op.type == OP_TYPE_IMM:
                        all_operands[i] = op_asm
                    elif op.type == OP_TYPE_MEM:
                        if self.binary.syntax == 'intel':
                            all_operands[i] = all_operands[i][ : all_operands[i].index('ptr') + 3] + " [" + op_asm + "]"
                        elif self.binary.syntax == 'at&t':
                            all_operands[i] = op_asm

                    if self.capstone_operand_types[i] == CS_OP_IMM:
                        if mnemonic.startswith('j') or mnemonic.startswith('call') or mnemonic.startswith('loop') or \
                            self.project.arch.name in ['PPC32', 'ARMEL']:
                            pass
                        else:
                            sub_prefix = "$"
                            if self.project.arch.name in ['MIPS32']:
                                sub_prefix = ""
                            # mark the size of the variable
                            if op.is_dataref:
                                op.label.var_size = op.size
                            if self.binary.syntax == 'at&t':
                                all_operands[i] = sub_prefix + all_operands[i]
                            else:
                                all_operands[i] = 'OFFSET FLAT:' + all_operands[i]

            asm = "\t%s%s" % (mnemonic, "\t" + ", ".join(all_operands))

        if self.addr in self.binary._removed_instructions:
            contents = [dbg_comments, inserted_asm_before_label, labels, inserted_asm_after_label]
        else:
            contents = [ dbg_comments, inserted_asm_before_label, labels, inserted_asm_after_label, asm ]
        contents = [ a for a in contents if a ]

        return "\n".join(contents)

    #
    # Private methods
    #

    def _initialize(self, capstone_operands):
        """
        Initialize this object

        :return: None
        """

        if self.addr is None:
            raise InstructionError('self.addr must be specified')

        self._initialize_operands(capstone_operands)

    def _initialize_operands(self, capstone_operands):
        """

        :return:
        """

        all_operands = split_operands(self.op_str)
        capstone_operands = capstone_operands[ - len(all_operands) : ] # sometimes there are more operands than expected...

        for operand, operand_str in zip(capstone_operands, all_operands):
            self.operands.append(Operand(self.binary, self.addr, self.size, operand, operand_str, self.mnemonic))

