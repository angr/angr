
import logging
import re
import string
import struct
from collections import defaultdict
from itertools import count

import capstone
import cle
import networkx
import pyvex

from . import Analysis
from .cfg.cfg_emulated import CFGEmulated
from .ddg import DDG
from .cfg.cfg_fast import CFGFast
from ..codenode import CodeNode
from ..knowledge_plugins.cfg.memory_data import MemoryDataSort
from ..knowledge_plugins.functions import Function
from ..knowledge_base import KnowledgeBase
from ..sim_variable import SimMemoryVariable, SimTemporaryVariable

l = logging.getLogger(name=__name__)


#
# Exceptions
#

class BinaryError(Exception):
    pass


class InstructionError(BinaryError):
    pass


class ReassemblerFailureNotice(BinaryError):
    pass

#
# Constants
#

OP_TYPE_REG = 1
OP_TYPE_IMM = 2
OP_TYPE_MEM = 3
OP_TYPE_RAW = 4

OP_TYPE_MAP = {
    OP_TYPE_REG: 'REG',
    OP_TYPE_IMM: 'IMM',
    OP_TYPE_MEM: 'MEM',
    OP_TYPE_RAW: 'RAW',
}

CAPSTONE_OP_TYPE_MAP = {
    'X86': {
        capstone.x86.X86_OP_REG: OP_TYPE_REG,
        capstone.x86.X86_OP_IMM: OP_TYPE_IMM,
        capstone.x86.X86_OP_MEM: OP_TYPE_MEM,
    },
    'AMD64': {
        capstone.x86.X86_OP_REG: OP_TYPE_REG,
        capstone.x86.X86_OP_IMM: OP_TYPE_IMM,
        capstone.x86.X86_OP_MEM: OP_TYPE_MEM,
    },
}

CAPSTONE_REG_MAP = {
    # will be filled up by fill_reg_map()
    'X86': {
    },
    'AMD64': {
    }
}

# Utils

def string_escape(s):

    if isinstance(s, bytes):
        s = "".join(chr(i) for i in s)

    s = s.encode('unicode_escape').decode("utf-8")

    s = s.replace("\\'", "'")
    s = s.replace("\"", "\\\"")

    return s

def fill_reg_map():
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

fill_reg_map()


class Label:
    g_label_ctr = count()

    def __init__(self, binary, name, original_addr=None):

        self.binary = binary
        self.name = name

        self.assigned = False

        self.var_size = None

        if self.name is None:
            self.name = "label_%d" % next(Label.g_label_ctr)

        self.original_addr = original_addr
        self.base_addr = None

    #
    # Overridden predefined methods
    #

    def __str__(self):
        """

        :return:
        """

        #if self.var_size is not None:
        #    s = ".type {name},@object\n.comm {name},{size},{size}".format(name=self.name, size=self.var_size)
        #else:
        s = ".{name}:".format(name=self.name)
        return s

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        return self.name == other.name

    #
    # Properties
    #

    @property
    def operand_str(self):
        if self.base_addr is None:
            return ".%s" % self.name
        else:
            offset = self.offset
            sign = '+' if offset >= 0 else '-'
            offset = abs(offset)
            return ".%s%s%d" % (self.name, sign, offset)

    @property
    def offset(self):
        if self.base_addr is None:
            return 0
        return self.original_addr - self.base_addr

    #
    # Static methods
    #

    @staticmethod
    def new_label(binary, name=None, function_name=None, original_addr=None, data_label=False):
        if function_name is not None:
            return FunctionLabel(binary, function_name, original_addr)
        elif data_label:
            return DataLabel(binary, original_addr)
        else:
            return Label(binary, name, original_addr=original_addr)


class DataLabel(Label):
    def __init__(self, binary, original_addr, name=None):
        Label.__init__(self, binary, name, original_addr=original_addr)

    @property
    def operand_str(self):
        if self.base_addr is None:
            return self.name
        else:
            offset = self.offset
            sign = '+' if offset >= 0 else '-'
            offset = abs(offset)
            return '(%s%s%s)' % (self.name, sign, offset)

    def __str__(self):
        #if self.var_size is not None:
        #    s = ".comm {name},{size},{size}".format(name=self.name, size=self.var_size)
        #else:
        s = "%s:" % (self.name)
        return s


class FunctionLabel(Label):
    def __init__(self, binary, function_name, original_addr, plt=False):
        Label.__init__(self, binary, function_name, original_addr=original_addr)

        self.plt = plt

    @property
    def function_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {func_name}\n" +
                "\t.type {func_name}, @function\n" +
                "{func_name}:").format(
            func_name=self.function_name
        )


class ObjectLabel(Label):
    def __init__(self, binary, symbol_name, original_addr, plt=False):
        Label.__init__(self, binary, symbol_name, original_addr=original_addr)

        self.plt = plt

    @property
    def symbol_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {symbol_name}\n" +
                "\t.type {symbol_name}, @object\n" +
                "{symbol_name}:").format(
            symbol_name=self.symbol_name
        )


class NotypeLabel(Label):
    def __init__(self, binary, symbol_name, original_addr, plt=False):
        Label.__init__(self, binary, symbol_name, original_addr=original_addr)

        self.plt = plt

    @property
    def symbol_name(self):
        return self.name

    @property
    def operand_str(self):
        return self.name

    def __str__(self):
        return ("\t.globl {symbol_name}\n" +
                "\t.type {symbol_name}, @notype\n" +
                "{symbol_name}:").format(
            symbol_name=self.symbol_name
        )


class SymbolManager:
    """
    SymbolManager manages all symbols in the binary.
    """
    def __init__(self, binary, cfg):
        """
        Constructor.

        :param Reassembler binary: The Binary analysis instance.
        :param angr.analyses.CFG cfg: The CFG analysis instance.
        :return: None
        """

        self.binary = binary
        self.project = binary.project
        self.cfg = cfg

        self.addr_to_label = defaultdict(list)
        self.symbol_names = set()  # deduplicate symbol names

    def get_unique_symbol_name(self, symbol_name):
        if symbol_name not in self.symbol_names:
            self.symbol_names.add(symbol_name)
            return symbol_name

        i = 0
        while True:
            name = "%s_%d" % (symbol_name, i)
            if name not in self.symbol_names:
                self.symbol_names.add(name)
                return name
            i += 1

    def new_label(self, addr, name=None, is_function=None, force=False):

        if force:
            if self.binary.main_nonexecutable_regions_contain(addr):
                label = DataLabel(self.binary, addr, name=name)
            else:
                label = Label.new_label(self.binary, name=name, original_addr=addr)
            self.addr_to_label[addr].append(label)
            return label

        if addr in self.addr_to_label:
            return self.addr_to_label[addr][0]

        # Check if the address points to a function by checking the plt of main binary
        reverse_plt = self.project.loader.main_object.reverse_plt

        if addr in reverse_plt:
            # It's a PLT entry!
            label = FunctionLabel(self.binary, reverse_plt[addr], addr, plt=True)
        elif addr is not None and self.project.loader.find_symbol(addr) is not None:
            # It's an extern symbol
            symbol = self.project.loader.find_symbol(addr)
            if symbol.owner is self.project.loader.main_object:
                symbol_name = symbol.name
                if '@' in symbol_name:
                    symbol_name = symbol_name[ : symbol_name.index('@') ]

                # check the type...
                if symbol.type == cle.SymbolType.TYPE_FUNCTION:
                    # it's a function!
                    unique_symbol_name = self.get_unique_symbol_name(symbol_name)
                    label = FunctionLabel(self.binary, unique_symbol_name, addr)
                elif symbol.type == cle.SymbolType.TYPE_OBJECT:
                    # it's an object
                    unique_symbol_name = self.get_unique_symbol_name(symbol_name)
                    label = ObjectLabel(self.binary, unique_symbol_name, addr)
                elif symbol.type == cle.SymbolType.TYPE_NONE:
                    # notype
                    unique_symbol_name = self.get_unique_symbol_name(symbol_name)
                    label = NotypeLabel(self.binary, unique_symbol_name, addr)
                elif symbol.type == cle.SymbolType.TYPE_SECTION:
                    # section label
                    # use a normal label instead
                    if not name:
                        # handle empty names
                        name = None
                    label = Label.new_label(self.binary, name=name, original_addr=addr)
                else:
                    raise Exception('Unsupported symbol type %s. Bug Fish about it!' % symbol.type)

            else:
                raise Exception("the symbol %s is not owned by the main object. Try reload the project with"
                                "\"auto_load_libs=False\". If that does not solve the issue, please report to GitHub."
                                % symbol.name
                                )

        elif (addr is not None and addr in self.cfg.functions) or is_function:
            # It's a function identified by angr's CFG recovery

            if is_function and name is not None:
                function_name = name
            else:
                function_name = self.cfg.functions[addr].name

                # special function name for entry point
                if addr == self.project.entry:
                    function_name = "_start"

            label = FunctionLabel(self.binary, function_name, addr)
        elif addr is not None and self.binary.main_nonexecutable_regions_contain(addr):
            label = DataLabel(self.binary, addr)
        else:
            label = Label.new_label(self.binary, name=name, original_addr=addr)

        if addr is not None:
            self.addr_to_label[addr].append(label)

        return label

    def label_got(self, addr, label):
        """
        Mark a certain label as assigned (to an instruction or a block of data).

        :param int addr: The address of the label.
        :param angr.analyses.reassembler.Label label:
                         The label that is just assigned.
        :return: None
        """

        if label in self.addr_to_label[addr]:
            label.assigned = True


class Operand:
    def __init__(self, binary, insn_addr, insn_size, capstone_operand, operand_str, mnemonic, operand_offset, syntax=None):
        """
        Constructor.

        :param Reassembler binary: The Binary analysis.
        :param int insn_addr: Address of the instruction.
        :param capstone_operand:
        :param str operand_str: the string representation of this operand
        :param str mnemonic: Mnemonic of the instruction that this operand belongs to.
        :param int operand_offset: offset of the operand into the instruction.
        :param str syntax: Provide a way to override the default syntax coming from `binary`.
        :return: None
        """

        self.binary = binary
        self.project = binary.project
        self.insn_addr = insn_addr
        self.insn_size = insn_size
        self.operand_str = operand_str
        self.mnemonic = mnemonic
        self.operand_offset = operand_offset
        self.syntax = self.binary.syntax if syntax is None else syntax
        self.type = None
        self.size = capstone_operand.size

        # IMM
        self.is_coderef = None
        self.is_dataref = None
        self.label = None
        self.label_offset = 0

        # MEM
        self.base = None
        self.index = None
        self.scale = None
        self.disp = None

        # RAW
        self.raw_asm = None

        self.disp_is_coderef = None
        self.disp_is_dataref = None
        self.disp_label = None
        self.disp_label_offset = 0

        self._initialize(capstone_operand)

    #
    # Public methods
    #

    def assembly(self):
        if self.type == OP_TYPE_IMM and self.label:
            if self.label_offset > 0:
                return "%s + %d" % (self.label.operand_str, self.label_offset)
            elif self.label_offset < 0:
                return "%s - %d" % (self.label.operand_str, abs(self.label_offset))
            else:
                return self.label.operand_str

        elif self.type == OP_TYPE_MEM:

            disp = ""
            if self.disp:
                if self.disp_label:
                    if self.disp_label_offset > 0:
                        disp = "%s + %d" % (self.disp_label.operand_str, self.disp_label_offset)
                    elif self.disp_label_offset < 0:
                        disp = "%s - %d" % (self.disp_label.operand_str, abs(self.disp_label_offset))
                    else:
                        disp = self.disp_label.operand_str
                else:
                    disp = "%d" % self.disp

            base = ""
            if self.base:
                base = CAPSTONE_REG_MAP[self.project.arch.name][self.base]

            if self.syntax == 'at&t':
                # displacement(base, index, scale)
                base = "%%%s" % base if base else ""

                if "*" in self.operand_str and disp:
                    # absolute memory address
                    disp = "*" + disp

                if self.index:
                    s = "%s(%s, %%%s, %d)" % (disp, base, CAPSTONE_REG_MAP[self.project.arch.name][self.index],
                                              self.scale
                                              )
                elif self.base:  # not self.index
                    s = "%s(%s)" % (disp, base)
                else:
                    s = disp

                return s

            else:
                s = [ ]
                if base:
                    s.append(base)

                if self.index and self.scale:
                    if s:
                        s.append('+')
                    s.append("(%s * %d)" % (CAPSTONE_REG_MAP[self.project.arch.name][self.index], self.scale))

                if disp:
                    if disp.startswith('-'):
                        s.append('-')
                        s.append(disp[1:])
                    else:
                        if s:
                            s.append('+')
                        s.append(disp)

                asm = " ".join(s)

                # we need to specify the size here
                if self.size == 16:
                    asm = 'xmmword ptr [%s]' % asm
                elif self.size == 10:
                    asm = 'xword ptr [%s]' % asm
                elif self.size == 8:
                    asm = 'qword ptr [%s]' % asm
                elif self.size == 4:
                    asm = 'dword ptr [%s]' % asm
                elif self.size == 2:
                    asm = 'word ptr [%s]' % asm
                elif self.size == 1:
                    asm = 'byte ptr [%s]' % asm
                else:
                    raise BinaryError('Unsupported memory operand size for operand "%s"' % self.operand_str)

                return asm

        elif self.type == OP_TYPE_RAW:
            return self.raw_asm

        else:
            # Nothing special
            return None

    #
    # Overridden predefined methods
    #

    def __str__(self):
        """

        :return:
        """

        op_type = OP_TYPE_MAP[self.type]

        ref_type = ""
        if self.is_coderef:
            ref_type = "CODEREF"
        elif self.is_dataref:
            ref_type = "DATAREF"

        if ref_type:
            return "%s <%s>" % (op_type, ref_type)
        else:
            return op_type

    #
    # Properties
    #

    @property
    def is_immediate(self):
        return self.type == OP_TYPE_IMM

    @property
    def symbolized(self):
        return self.label is not None or self.disp_label is not None

    #
    # Private methods
    #

    def _initialize(self, capstone_operand):

        arch_name = self.project.arch.name
        self.type = CAPSTONE_OP_TYPE_MAP[arch_name][capstone_operand.type]

        if self.type == OP_TYPE_IMM:
            # Check if this is a reference to code
            imm = capstone_operand.imm

            self.is_coderef, self.is_dataref, baseaddr = \
                self._imm_to_ptr(imm, self.type, self.mnemonic)

            if self.is_coderef or self.is_dataref:
                self.label = self.binary.symbol_manager.new_label(addr=baseaddr)
                self.label_offset = imm - baseaddr

                if self.mnemonic.startswith('j') or self.mnemonic.startswith('loop'):
                    sort = 'jump'
                elif self.mnemonic.startswith('call'):
                    sort = 'call'
                else:
                    sort = 'absolute'
                self.binary.register_instruction_reference(self.insn_addr, imm, sort, self.operand_offset)

        elif self.type == OP_TYPE_MEM:

            self.base = capstone_operand.mem.base
            self.index = capstone_operand.mem.index
            self.scale = capstone_operand.mem.scale
            self.disp = capstone_operand.mem.disp

            if self.binary.project.arch.name == 'AMD64' and CAPSTONE_REG_MAP['AMD64'][self.base] == 'rip':
                # rip-relative addressing
                self.disp += self.insn_addr + self.insn_size

            self.disp_is_coderef, self.disp_is_dataref, baseaddr = \
                self._imm_to_ptr(self.disp, self.type, self.mnemonic)

            if self.disp_is_coderef or self.disp_is_dataref:
                self.disp_label = self.binary.symbol_manager.new_label(addr=baseaddr)
                self.disp_label_offset = self.disp - baseaddr

                self.binary.register_instruction_reference(self.insn_addr, self.disp, 'absolute', self.operand_offset)

    def _imm_to_ptr(self, imm, operand_type, mnemonic):  # pylint:disable=no-self-use,unused-argument
        """
        Try to classify an immediate as a pointer.

        :param int imm: The immediate to test.
        :param int operand_type: Operand type of this operand, can either be IMM or MEM.
        :param str mnemonic: Mnemonic of the instruction that this operand belongs to.
        :return: A tuple of (is code reference, is data reference, base address, offset)
        :rtype: tuple
        """

        is_coderef, is_dataref = False, False
        baseaddr = None

        if not is_coderef and not is_dataref:
            if self.binary.main_executable_regions_contain(imm):
                # does it point to the beginning of an instruction?
                if imm in self.binary.all_insn_addrs:
                    is_coderef = True
                    baseaddr = imm

        if not is_coderef and not is_dataref:
            if self.binary.main_nonexecutable_regions_contain(imm):
                is_dataref = True
                baseaddr = imm

        if not is_coderef and not is_dataref:
            tolerance_before = 1024 if operand_type == OP_TYPE_MEM else 64
            contains_, baseaddr_ = self.binary.main_nonexecutable_region_limbos_contain(imm,
                                                                                        tolerance_before=tolerance_before,
                                                                                        tolerance_after=1024
                                                                                        )
            if contains_:
                is_dataref = True
                baseaddr = baseaddr_

            if not contains_:
                contains_, baseaddr_ = self.binary.main_executable_region_limbos_contain(imm)
                if contains_:
                    is_coderef = True
                    baseaddr = baseaddr_

        return (is_coderef, is_dataref, baseaddr)


class Instruction:
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

        operand_offsets = [ ]
        for operand in capstone_instr.operands:
            if operand.type == capstone.CS_OP_IMM:
                operand_offsets.append(capstone_instr.imm_offset)
            elif operand.type == capstone.CS_OP_MEM:
                operand_offsets.append(capstone_instr.disp_offset)
            else:
                operand_offsets.append(None)

        if self.addr is not None:
            self._initialize(capstone_instr.operands, operand_offsets)

    #
    # Overridden predefined instructions
    #
    def __str__(self):
        """

        :return:
        """

        assembly = self.assembly(comments=True, symbolized=False)
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

        elif not any([ (operand.symbolized or operand.type == OP_TYPE_RAW) for operand in self.operands ]):
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
                    if op.type in (OP_TYPE_IMM, OP_TYPE_MEM, OP_TYPE_RAW):
                        all_operands[i] = op_asm
                    else:
                        raise BinaryError("Unsupported operand type %d." % op.type)

                    if op.type != OP_TYPE_RAW and self.capstone_operand_types[i] == capstone.CS_OP_IMM:
                        if mnemonic.startswith('j') or mnemonic.startswith('call') or mnemonic.startswith('loop'):
                            pass
                        else:
                            # mark the size of the variable
                            if op.is_dataref:
                                op.label.var_size = op.size
                            if self.binary.syntax == 'at&t':
                                all_operands[i] = "$" + all_operands[i]
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

    def _initialize(self, capstone_operands, operand_offsets):
        """
        Initialize this object

        :return: None
        """

        if self.addr is None:
            raise InstructionError('self.addr must be specified')

        self._initialize_operands(capstone_operands, operand_offsets)

    def _initialize_operands(self, capstone_operands, operand_offsets):
        """

        :return:
        """

        all_operands = split_operands(self.op_str)
        capstone_operands = capstone_operands[ - len(all_operands) : ] # sometimes there are more operands than expected...
        operand_offsets = operand_offsets[ - len(all_operands) : ]

        for operand, operand_str, offset in zip(capstone_operands, all_operands, operand_offsets):
            self.operands.append(Operand(self.binary, self.addr, self.size, operand, operand_str, self.mnemonic, offset))

class BasicBlock:
    """
    BasicBlock represents a basic block in the binary.
    """
    def __init__(self, binary, addr, size, x86_getpc_retsite: bool=False):
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
        self.x86_getpc_retsite = x86_getpc_retsite

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
        s = "\n".join([ins.assembly(comments=comments, symbolized=symbolized) for ins in self.instructions])

        return s

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
        for idx, instr in enumerate(capstone_obj.insns):
            # special handling for X86 PIE binaries
            instruction = Instruction(self.binary, instr.address, instr.size, None, instr)

            if self.x86_getpc_retsite and idx == 0:
                if (self.binary.syntax == "at&t"
                        and instr.mnemonic == "addl"
                        and instr.operands[1].type == capstone.CS_OP_REG
                        and instr.operands[0].type == capstone.CS_OP_IMM
                ):
                    instruction.operands[0].type = OP_TYPE_RAW
                    instruction.operands[0].raw_asm = "$_GLOBAL_OFFSET_TABLE_"
                elif (self.binary.syntax == "intel"
                        and instr.mnemonic == "add"
                        and instr.operands[0].type == capstone.CS_OP_REG
                        and instr.operands[1].type == capstone.CS_OP_IMM
                ):
                    instruction.operands[1].type == OP_TYPE_RAW
                    instruction.operands[1].raw_asm = "OFFSET FLAG:_GLOBAL_OFFSET_TABLE_"

            self.instructions.append(instruction)

        self.instructions = sorted(self.instructions, key=lambda x: x.addr)

class Procedure:
    """
    Procedure in the binary.
    """
    def __init__(self, binary, function=None, addr=None, size=None, name=None, section=".text", asm_code=None):
        """
        Constructor.

        :param Reassembler binary: The Binary analysis.
        :param angr.knowledge.Function function: The function it represents
        :param int addr: Address of the function. Not required if `function` is provided.
        :param int size: Size of the function. Not required if `function` is provided.
        :param str section: Which section this function comes from.
        :return: None
        """

        self.binary = binary
        self.project = binary.project

        if function is None:
            self.addr = addr
            self.size = size

            self.function = None
            self._name = name

        else:
            self.addr = function.addr
            self.size = None # FIXME:

            self.function = function
            self._name = function.name

        self.asm_code = asm_code
        self.section = section

        self.blocks = [ ]

        self._initialize()

    #
    # Attributes
    #

    @property
    def name(self):
        """
        Get function name from the labels of the very first block.
        :return: Function name if there is any, None otherwise
        :rtype: string
        """

        if self._name is not None:
            return self._name

        if not self.blocks:
            return None

        if not self.blocks[0].instructions:
            return None

        if not self.blocks[0].instructions[0].labels:
            return None

        lbl = self.blocks[0].instructions[0].labels[0]

        if isinstance(lbl, FunctionLabel):
            return lbl.function_name

        return None

    @property
    def is_plt(self):
        """
        If this function is a PLT entry or not.
        :return: True if this function is a PLT entry, False otherwise
        :rtype: bool
        """

        if self.section == ".plt":
            return True

        if not self.blocks:
            return False

        initial_block = next((b for b in self.blocks if b.addr == self.addr), None)
        if initial_block is None:
            return False

        if not initial_block.instructions:
            return False

        if not initial_block.instructions[0].labels:
            return False

        lbl = initial_block.instructions[0].labels[0]

        if isinstance(lbl, FunctionLabel):
            return lbl.plt

        return False

    #
    # Overridden predefined methods
    #
    def __str__(self):
        """
        Output all instructions of the current procedure
        :return:
        """

        return self.assembly(symbolized=False)

    #
    # Public methods
    #

    def assign_labels(self):
        for block in self.blocks:
            block.assign_labels()

    def assembly(self, comments=False, symbolized=True):
        """
        Get the assembly manifest of the procedure.

        :param comments:
        :param symbolized:
        :return: A list of tuples (address, basic block assembly), ordered by basic block addresses
        :rtype: list
        """

        assembly = [ ]

        header = "\t.section\t{section}\n\t.align\t{alignment}\n".format(section=self.section,
                                                 alignment=self.binary.section_alignment(self.section)
                                                 )
        if self.addr is not None:
            procedure_name = "%#x" % self.addr
        else:
            procedure_name = self._name
        header += "\t#Procedure %s\n" % procedure_name

        if self._output_function_label:
            if self.addr:
                function_label = self.binary.symbol_manager.new_label(self.addr)
            else:
                function_label = self.binary.symbol_manager.new_label(None, name=procedure_name, is_function=True)
            header += str(function_label) + "\n"

        assembly.append((self.addr, header))

        if self.asm_code:
            s = self.asm_code
            assembly.append((self.addr, s))
        elif self.blocks:
            for b in sorted(self.blocks, key=lambda x:x.addr):  # type: BasicBlock
                s = b.assembly(comments=comments, symbolized=symbolized)
                assembly.append((b.addr, s))

        return assembly

    def instruction_addresses(self):
        """
        Get all instruction addresses in the binary.

        :return: A list of sorted instruction addresses.
        :rtype: list
        """

        addrs = [ ]
        for b in sorted(self.blocks, key=lambda x: x.addr):  # type: BasicBlock
            addrs.extend(b.instruction_addresses())

        return sorted(set(addrs), key=lambda x: x[0])

    #
    # Private methods
    #

    def _initialize(self):

        if self.function is None:
            if not self.asm_code:
                raise BinaryError('Unsupported procedure type. You must either specify a angr.knowledge.Function '
                                  'object, or specify assembly code.')


        else:
            x86_getpc_retsites = set()
            if self.project.arch.name == "X86":
                if 'pc_reg' in self.function.info:
                    # this is an x86-PIC function that calls a get_pc thunk
                    # we need to fix the "add e{a,b,c}x, offset" instruction right after the get_pc call
                    # first let's identify which function is the get_pc function
                    for src, dst, data in self.function.transition_graph.edges(data=True):
                        if isinstance(src, CodeNode) and isinstance(dst, Function):
                            if 'get_pc' in dst.info:
                                # found it!
                                x86_getpc_retsites.add(src.addr + src.size)
            for block_addr in self.function.block_addrs:
                b = BasicBlock(self.binary, block_addr, self.function._block_sizes[block_addr],
                               x86_getpc_retsite=block_addr in x86_getpc_retsites)
                self.blocks.append(b)

            self.blocks = sorted(self.blocks, key=lambda x: x.addr)

    @property
    def _output_function_label(self):
        """
        Determines if we want to output the function label in assembly. We output the function label only when the
        original instruction does not output the function label.

        :return: True if we should output the function label, False otherwise.
        :rtype: bool
        """

        if self.asm_code:
            return True
        if not self.blocks:
            return True

        the_block = next((b for b in self.blocks if b.addr == self.addr), None)
        if the_block is None:
            return True
        if not the_block.instructions:
            return True
        if not the_block.instructions[0].labels:
            return True
        return False

class ProcedureChunk(Procedure):
    """
    Procedure chunk.
    """
    def __init__(self, project, addr, size):
        """
        Constructor.

        :param project:
        :param addr:
        :param size:
        :return:
        """

        Procedure.__init__(self, project, addr=addr, size=size)


class Data:
    def __init__(self, binary, memory_data=None, section=None, section_name=None, name=None, size=None, sort=None,
                 addr=None, initial_content=None):

        self.binary = binary
        self.project = binary.project
        self.memory_data = memory_data
        self.section = section
        self.section_name = section.name if section else section_name

        self.addr = addr
        self.name = name
        self.size = size
        self.sort = sort
        self._initial_content = initial_content  # only used by patcherex

        self._content = None

        self.labels = [ ] # a list of tuples like (address, label)
        self.end_labels = [ ]  # a list of labels only show up at the end of this memory data entry. mostly because the
                               # data block after this one is removed for some reason. only assigned by other methods.

        self.null_terminated = None

        self.skip = False

        self._initialize()

    def __repr__(self):
        return "<DataItem %s@%#08x, %d bytes>" % (self.sort, self.addr, self.size)

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, v):
        self._content = v

    def shrink(self, new_size):
        """
        Reduce the size of this block

        :param int new_size: The new size
        :return: None
        """
        self.size = new_size

        if self.sort == MemoryDataSort.String:
            self.null_terminated = False # string without the null byte terminator
            self._content[0] = self._content[0][ : self.size]

        elif self.sort == MemoryDataSort.PointerArray:
            pointer_size = self.binary.project.arch.bytes

            if self.size % pointer_size != 0:
                # it's not aligned?
                raise BinaryError('Fails at Data.shrink()')

            pointers = self.size // pointer_size
            self._content = self._content[ : pointers]

        else:
            # unknown
            self._content =  [ self._content[0][ : self.size ] ]

    def desymbolize(self):
        """
        We believe this was a pointer and symbolized it before. Now we want to desymbolize it.

        The following actions are performed:
        - Reload content from memory
        - Mark the sort as 'unknown'

        :return: None
        """

        self.sort = MemoryDataSort.Unknown
        content = self.binary.fast_memory_load(self.addr, self.size, bytes)
        self.content = [ content ]

    def assign_labels(self):

        # TODO: What if it's not aligned for some sort of data, like pointer array?

        if self.addr is None:
            # this piece of data comes from a patch, not from the original binary
            return

        # Put labels to self.labels
        for i in range(self.size):
            addr = self.addr + i
            if addr in self.binary.symbol_manager.addr_to_label:
                labels = self.binary.symbol_manager.addr_to_label[addr]

                for label in labels:
                    if self.sort == MemoryDataSort.PointerArray and addr % (self.project.arch.bytes) != 0:
                        # we need to modify the base address of the label
                        base_addr = addr - (addr % (self.project.arch.bytes))
                        label.base_addr = base_addr
                        tpl = (base_addr, label)
                        if tpl not in self.labels:
                            self.labels.append(tpl)
                    else:
                        tpl = (addr, label)
                        if tpl not in self.labels:
                            self.labels.append(tpl)

    def assembly(self, comments=False, symbolized=True):
        s = ""

        if comments:
            if self.addr is not None:
                s += "\t# data @ %#08x\n" % self.addr
            else:
                s += "\t# data (%s)\n" % self.name

        if self.skip:
            return s

        if self.sort == MemoryDataSort.String:

            if symbolized:
                ss = [ ]
                last_pos = 0
                for i, tpl in enumerate(self.labels):
                    addr, lbl = tpl

                    # split the string
                    pos = addr - self.addr
                    # endpos = self.labels[i + 1][0] - self.addr + 1 if i < len(self.labels) - 1 else self.size
                    string_piece = self.content[0][last_pos : pos]

                    last_pos = pos

                    if i == len(self.labels) - 1 and pos == self.size:
                        directive = '.asciz' # null at the end
                    else:
                        directive = '.ascii'

                    if string_piece:
                        ss.append("\t{directive} \"{str}\"".format(
                            str=string_escape(string_piece),
                            directive=directive,
                            )
                        )
                    ss.append("%s" % str(lbl))

                if last_pos <= self.size - 1:
                    string_piece = self.content[0][last_pos: ]
                    directive = ".ascii" if self.null_terminated is False else ".asciz"

                    ss.append("\t{directive} \"{str}\"".format(
                        str=string_escape(string_piece),
                        directive=directive,
                    ))

                s += "\n".join(ss)
            else:
                if self.null_terminated is False:
                    directive = ".ascii"
                else:
                    directive = ".asciz"
                s += "\t.{directive} \"{str}\"".format(directive=directive, str=string_escape(self.content[0]))
            s += '\n'

        elif self.sort == MemoryDataSort.PointerArray:

            if self.binary.project.arch.bits == 32:
                directive = '.long'
            elif self.binary.project.arch.bits == 64:
                directive = '.quad'
            else:
                raise BinaryError('Unsupported pointer size %d', self.binary.project.arch.bits)

            if symbolized:
                addr_to_labels = {}
                for k, v in self.labels:
                    if k not in addr_to_labels:
                        addr_to_labels[k] = [ ]
                    addr_to_labels[k].append(v)

                i = 0
                if self.name is not None:
                    s += "%s:\n" % self.name
                for symbolized_label in self.content:

                    if self.addr is not None and (self.addr + i) in addr_to_labels:
                        for label in addr_to_labels[self.addr + i]:
                            s += "%s\n" % str(label)
                    elif self.addr is not None and (self.addr + i) in self.binary.symbol_manager.addr_to_label:
                        labels = self.binary.symbol_manager.addr_to_label[self.addr + i]
                        for label in labels:
                            s += "%s\n" % str(label)
                    i += self.project.arch.bytes

                    if isinstance(symbolized_label, int):
                        s += "\t%s %d\n" % (directive, symbolized_label)
                    else:
                        s += "\t%s %s\n" % (directive, symbolized_label.operand_str)

            else:
                for label in self.content:
                    s += "\t%s %s\n" % (directive, label.operand_str)

        elif self.sort == MemoryDataSort.SegmentBoundary:

            if symbolized:
                for _, label in self.labels:
                    s += "\t%s\n" % str(label)

        elif self.sort == MemoryDataSort.Integer:
            # display it as bytes only when there are references pointing to the middle
            content = [ ]

            if self.size == 1:
                directive = '.byte'
                fmt_str = 'B'
            elif self.size == 2:
                directive = '.short'
                fmt_str = '<H'
            elif self.size == 4:
                directive = '.long'
                fmt_str = '<I'
            elif self.size == 8:
                directive = '.quad'
                fmt_str = '<Q'
            else:
                # we'll have to display it as a bunch of bytes
                directive = None
                fmt_str = None

            if symbolized:
                addr_to_labels = {}
                for k, v in self.labels:
                    if k not in addr_to_labels:
                        addr_to_labels[k] = []
                    addr_to_labels[k].append(v)

                show_integer = False
                if len(addr_to_labels) == 0:
                    show_integer = True
                elif len(addr_to_labels) == 1:
                    if self.addr is not None and next(iter(addr_to_labels.keys())) == self.addr:
                        show_integer = True
                    elif self.addr is None and next(iter(addr_to_labels.keys())) == 0:
                        show_integer = True

                if directive is not None and show_integer:
                    # nice, we should display it as an integer
                    if addr_to_labels:
                        for label in next(iter(addr_to_labels.values())):
                            content += [ "%s" % str(label) ]

                    integer = struct.unpack(fmt_str, self.content[0])[0]
                    content += ['\t{directive} {integer}'.format(
                        directive=directive,
                        integer='%#x' % integer,
                    )]

                else:
                    # display it as bytes...
                    addr = self.addr if self.addr is not None else 0
                    for piece in self.content:
                        for c in piece:
                            if addr in addr_to_labels:
                                for label in addr_to_labels[addr]:
                                    content += [ "%s" % str(label) ]
                            addr += 1

                            content += ['\t.byte %d' % c]

            else:
                integer = struct.unpack(fmt_str, self.content[0])[0]
                content += ['\t{directive} {integer}'.format(
                    directive=directive,
                    integer='%#x' % integer,
                )]

            s += "\n".join(content)
            s += "\n"

        elif self.sort == MemoryDataSort.FloatingPoint:
            # we have to display it as bytes...
            # TODO: switch to "ten byes" whenever time permits
            content = []

            if symbolized:
                addr_to_labels = {}
                for k, v in self.labels:
                    if k not in addr_to_labels:
                        addr_to_labels[k] = []
                    addr_to_labels[k].append(v)

                addr = self.addr if self.addr is not None else 0
                for piece in self.content:
                    for c in piece:
                        if addr in addr_to_labels:
                            for label in addr_to_labels[addr]:
                                content += [ "%s" % str(label) ]
                        addr += 1

                        content += ['\t.byte %d' % c]
            else:
                for piece in self.content:
                    content += ['\t.byte %d' % c for c in piece]

            s += "\n".join(content)
            s += "\n"

        else:
            content = []

            if symbolized:
                addr_to_labels = { }
                for k, v in self.labels:
                    if k not in addr_to_labels:
                        addr_to_labels[k] = []
                    addr_to_labels[k].append(v)

                addr = self.addr if self.addr is not None else 0
                for piece in self.content:
                    for c in piece:
                        if addr in addr_to_labels:
                            for label in addr_to_labels[addr]:
                                content += [ "%s" % str(label) ]
                        addr += 1

                        content += ['\t.byte %d' % c]
            else:
                for piece in self.content:
                    content += [ '\t.byte %d' % c for c in piece ]

            s += "\n".join(content)
            s += "\n"

        if self.end_labels:
            for label in self.end_labels:
                s += "%s\n" % label

        return s.strip("\n")

    #
    # Private methods
    #

    def _initialize(self):

        if self.memory_data is None:

            if self.size is None or self._initial_content is None and self.sort is None:
                raise BinaryError('You must at least specify size, initial_content, and sort.')

            if self.sort == MemoryDataSort.PointerArray:

                lbl = DataLabel(self.binary, -1, name=self.name)
                self.labels.append((0, lbl))

                # symbolize the pointer array

                self._content = [ ]

                fmt_str = ""
                if self.project.arch.memory_endness == 'Iend_LE':
                    fmt_str += "<"
                else:
                    fmt_str += ">"
                if self.project.arch.bits == 32:
                    fmt_str += "I"
                    pointer_size = 4
                else:
                    fmt_str += "Q"
                    pointer_size = 8

                for i in range(0, len(self._initial_content), pointer_size):
                    addr_str = self._initial_content[i : i + pointer_size]
                    addr = struct.unpack(fmt_str, addr_str)[0]
                    if addr != 0 and (
                                self.binary.main_executable_regions_contain(addr) or
                                self.binary.main_nonexecutable_regions_contain(addr)
                    ):
                        label = self.binary.symbol_manager.new_label(addr)
                    else:
                        # it might be a pointer pointing to the binary base address or something
                        # just keep it as it is
                        # TODO: some more delicate logic should be applied here. For example, if the pointer is very
                        # TODO: close to the beginning of .text, but after reassembling, it might be pointing to
                        # TODO: somewhere inside .text. In this case we'd like to fix up the reference and make it
                        # TODO: point to the beginning of .text minus an offset, instead of keeping the original header.
                        label = addr
                    self._content.append(label)

            elif self.sort in {MemoryDataSort.String, MemoryDataSort.Unknown, MemoryDataSort.Integer}:

                lbl = DataLabel(self.binary, -1, name=self.name)
                self.labels.append((0, lbl))

                self._content = [ self._initial_content ]

            elif self.sort == MemoryDataSort.SegmentBoundary:
                label = self.binary.symbol_manager.new_label(self.addr)
                self.labels.append((self.addr, label))
                self._content = []

            else:
                raise BinaryError('Unsupported data sort "%s"' % self.sort)

        else:
            self.addr = self.memory_data.address
            self.size = self.memory_data.size
            self.sort = self.memory_data.sort

            # Symbolize the content
            if self.sort == MemoryDataSort.PointerArray:
                # read out the address
                pointer_size = self.project.arch.bytes
                pointers = self.size // pointer_size

                self._content = []
                for i in range(pointers):
                    addr = self.binary.fast_memory_load(self.addr + i * pointer_size, pointer_size, int,
                                                        endness=self.project.arch.memory_endness
                                                        )
                    if addr is None:
                        continue
                    obj = self.project.loader.find_object_containing(addr)
                    if obj is self.project.loader.main_object:
                        # a dynamic pointer
                        if self.binary.main_executable_regions_contain(addr) or \
                                self.binary.main_nonexecutable_regions_contain(addr):
                            label = self.binary.symbol_manager.new_label(addr)
                            self._content.append(label)

                            self.binary.register_data_reference(self.addr + i * pointer_size, addr)

                        else:
                            # it's a pointer pointing to a segment, but not any section. keep it as it is
                            self._content.append(addr)
                    else:
                        # it's a static pointer. we should use the original pointer value.
                        self._content.append(addr)

            elif self.sort == MemoryDataSort.String:
                data = self.binary.fast_memory_load(self.addr, self.size, bytes)
                if data[-1] == 0:
                    self.null_terminated = True
                    data = data[:-1] # remove the null-byte. we'll use .asciz for it instead.
                else:
                    self.null_terminated = False

                self._content = [data]

            elif self.sort == MemoryDataSort.Integer:
                data = self.binary.fast_memory_load(self.addr, self.size, bytes)
                self._content = [ data ]

            elif self.sort == MemoryDataSort.SegmentBoundary:
                label = self.binary.symbol_manager.new_label(self.addr)
                self.labels.append((self.addr, label))

                self._content = [ ]

            elif self.sort == MemoryDataSort.FloatingPoint:
                # floating-point integers
                # Python has some trouble in dealing with floating point numbers
                # just store them as bytes
                data = self.binary.fast_memory_load(self.addr, self.size, bytes)
                self._content = [ data ]

            else:
                # other sorts
                content = self.binary.fast_memory_load(self.addr, self.size, bytes)
                if content is not None:
                    self._content = [content]
                else:
                    self._content = []


class Relocation:
    def __init__(self, addr, ref_addr, sort):
        self.addr = addr
        self.ref_addr = ref_addr
        self.sort = sort

    def __repr__(self):
        s = "<Reloc %s %#x (%#x)>" % (self.sort, self.addr, self.ref_addr)
        return s


class Reassembler(Analysis):
    """
    High-level representation of a binary with a linear representation of all instructions and data regions. After
    calling "symbolize", it essentially acts as a binary reassembler.

    Tested on CGC, x86 and x86-64 binaries.

    Discliamer: The reassembler is an empirical solution. Don't be surprised if it does not work on some binaries.
    """
    def __init__(self, syntax="intel", remove_cgc_attachments=True, log_relocations=True):

        self.syntax = syntax
        self._remove_cgc_attachments = remove_cgc_attachments

        self.symbol_manager = None
        self.cfg = None
        self._cgc_attachments_removed = False
        self.log_relocations = log_relocations

        self.procedures = [ ]
        self.data = [ ]

        self.extra_rodata = [ ]
        self.extra_data = [ ]

        self._main_executable_regions = None
        self._main_nonexecutable_regions = None

        self._symbolization_needed = True

        # section names to alignments
        self._section_alignments = {}

        # all instruction addresses
        self.all_insn_addrs = set()

        self._relocations = [ ]

        self._inserted_asm_before_label = defaultdict(list)
        self._inserted_asm_after_label = defaultdict(list)
        self._removed_instructions = set()

        self._initialize()

    #
    # Overridden predefined methods
    #

    def __str__(self):
        """
        Return a linear representation of all instructions in the binary
        :return:
        """

        s = "\n".join([str(proc) for proc in self.procedures])

        return s

    #
    # Properties
    #
    @property
    def instructions(self):
        """
        Get a list of all instructions in the binary

        :return: A list of (address, instruction)
        :rtype: tuple
        """

        raise NotImplementedError()

    @property
    def relocations(self):

        return self._relocations

    @property
    def inserted_asm_before_label(self):
        return self._inserted_asm_before_label

    @property
    def inserted_asm_after_label(self):
        return self._inserted_asm_after_label

    @property
    def main_executable_regions(self):
        """

        :return:
        """

        if self._main_executable_regions is None:
            self._main_executable_regions = []

            obj = self.project.loader.main_object

            if obj.sections:
                for sec in obj.sections:
                    if sec.is_executable:
                        min_addr = sec.min_addr
                        max_addr = sec.max_addr + 1
                        if max_addr <= min_addr or min_addr == 0:
                            continue
                        self._main_executable_regions.append((min_addr, max_addr))

            else:
                for seg in obj.segments:
                    if seg.is_executable:
                        min_addr = seg.min_addr
                        max_addr = seg.max_addr + 1
                        self._main_executable_regions.append((min_addr, max_addr))

        return self._main_executable_regions

    @property
    def main_nonexecutable_regions(self):
        """

        :return:
        """

        if self._main_nonexecutable_regions is None:
            self._main_nonexecutable_regions = []

            obj = self.project.loader.main_object

            if obj.sections:
                for sec in obj.sections:
                    if sec.name in {'.eh_frame', '.eh_frame_hdr'}:
                        # hack for ELF binaries...
                        continue
                    if not sec.is_executable:
                        min_addr = sec.min_addr
                        max_addr = sec.max_addr + 1
                        if max_addr <= min_addr or min_addr == 0:
                            continue
                        self._main_nonexecutable_regions.append((min_addr, max_addr))

            else:
                for seg in obj.segments:
                    if not seg.is_executable:
                        min_addr = seg.min_addr
                        max_addr = seg.max_addr + 1
                        self._main_nonexecutable_regions.append((min_addr, max_addr))

        return self._main_nonexecutable_regions

    #
    # Public methods
    #

    def section_alignment(self, section_name):
        """
        Get the alignment for the specific section. If the section is not found, 16 is used as default.

        :param str section_name: The section.
        :return: The alignment in bytes.
        :rtype: int
        """

        return self._section_alignments.get(section_name, 16)

    def main_executable_regions_contain(self, addr):
        """

        :param addr:
        :return:
        """
        for start, end in self.main_executable_regions:
            if start <= addr < end:
                return True
        return False

    def main_executable_region_limbos_contain(self, addr):
        """
        Sometimes there exists a pointer that points to a few bytes before the beginning of a section, or a few bytes
        after the beginning of the section. We take care of that here.

        :param int addr: The address to check.
        :return: A 2-tuple of (bool, the closest base address)
        :rtype: tuple
        """

        TOLERANCE = 64

        closest_region = None
        least_limbo = None

        for start, end in self.main_executable_regions:
            if start - TOLERANCE <= addr < start:
                if least_limbo is None or start - addr < least_limbo:
                    closest_region = (True, start)
                    least_limbo = start - addr
            if end <= addr < end + TOLERANCE:
                if least_limbo is None or addr - end < least_limbo:
                    closest_region = (True, end)
                    least_limbo = addr - end

        if closest_region is not None:
            return closest_region
        return (False, None)

    def main_nonexecutable_regions_contain(self, addr):
        """

        :param int addr: The address to check.
        :return: True if the address is inside a non-executable region, False otherwise.
        :rtype: bool
        """
        for start, end in self.main_nonexecutable_regions:
            if start <= addr < end:
                return True
        return False

    def main_nonexecutable_region_limbos_contain(self, addr, tolerance_before=64, tolerance_after=64):
        """
        Sometimes there exists a pointer that points to a few bytes before the beginning of a section, or a few bytes
        after the beginning of the section. We take care of that here.

        :param int addr: The address to check.
        :return: A 2-tuple of (bool, the closest base address)
        :rtype: tuple
        """

        closest_region = None
        least_limbo = None

        for start, end in self.main_nonexecutable_regions:
            if start - tolerance_before <= addr < start:
                if least_limbo is None or start - addr < least_limbo:
                    closest_region = (True, start)
                    least_limbo = start - addr
            if end <= addr < end + tolerance_after:
                if least_limbo is None or addr - end < least_limbo:
                    closest_region = (True, end)
                    least_limbo = addr - end

        if closest_region is not None:
            return closest_region
        return False, None

    def register_instruction_reference(self, insn_addr, ref_addr, sort, operand_offset):

        if not self.log_relocations:
            return

        addr = insn_addr + operand_offset
        r = Relocation(addr, ref_addr, sort)

        self._relocations.append(r)

    def register_data_reference(self, data_addr, ref_addr):

        if not self.log_relocations:
            return

        r = Relocation(data_addr, ref_addr, 'absolute')

        self._relocations.append(r)

    def add_label(self, name, addr):
        """
        Add a new label to the symbol manager.

        :param str name: Name of the label.
        :param int addr: Address of the label.
        :return: None
        """

        # set the label
        self._symbolization_needed = True

        self.symbol_manager.new_label(addr, name=name, force=True)

    def insert_asm(self, addr, asm_code, before_label=False):
        """
        Insert some assembly code at the specific address. There must be an instruction starting at that address.

        :param int addr: Address of insertion
        :param str asm_code: The assembly code to insert
        :return: None
        """

        if before_label:
            self._inserted_asm_before_label[addr].append(asm_code)
        else:
            self._inserted_asm_after_label[addr].append(asm_code)

    def append_procedure(self, name, asm_code):
        """
        Add a new procedure with specific name and assembly code.

        :param str name: The name of the new procedure.
        :param str asm_code: The assembly code of the procedure
        :return: None
        """

        proc = Procedure(self, name=name, asm_code=asm_code)
        self.procedures.append(proc)

    def append_data(self, name, initial_content, size, readonly=False, sort="unknown"):  # pylint:disable=unused-argument
        """
        Append a new data entry into the binary with specific name, content, and size.

        :param str name: Name of the data entry. Will be used as the label.
        :param bytes initial_content: The initial content of the data entry.
        :param int size: Size of the data entry.
        :param bool readonly: If the data entry belongs to the readonly region.
        :param str sort: Type of the data.
        :return: None
        """

        if readonly:
            section_name = ".rodata"
        else:
            section_name = '.data'

        if initial_content is None:
            initial_content = b""
        initial_content = initial_content.ljust(size, b"\x00")
        data = Data(self, memory_data=None, section_name=section_name, name=name, initial_content=initial_content,
                    size=size, sort=sort
                    )

        if section_name == '.rodata':
            self.extra_rodata.append(data)
        else:
            self.extra_data.append(data)

    def remove_instruction(self, ins_addr):
        """

        :param ins_addr:
        :return:
        """

        self._removed_instructions.add(ins_addr)

    def randomize_procedures(self):
        """

        :return:
        """

        raise NotImplementedError()

    def symbolize(self):

        # clear the flag
        self._symbolization_needed = False

        # sanity checks
        #if self._has_integer_used_as_pointers():
        #    raise ReassemblerFailureNotice('Integer-used-as-pointer detected. Reassembler will not work safely on '
        #                                   'this binary. Ping Fish if you believe the detection is wrong.'
        #                                   )

        for proc in self.procedures:
            proc.assign_labels()

        for data in self.data:
            data.assign_labels()

        # Get all instruction addresses, and modify those labels pointing to the middle of an instruction
        insn_addrs =  [ ]
        for proc in self.procedures:  # type: Procedure
            insn_addrs.extend(proc.instruction_addresses())
        # just to be safe
        insn_addrs = sorted(set(insn_addrs), key=lambda x: x[0])

        pos = 0

        changed_labels = [ ]

        for label_addr in sorted(self.symbol_manager.addr_to_label.keys()):
            while pos < len(insn_addrs) and label_addr > insn_addrs[pos][0]:
                pos += 1

            if pos >= len(insn_addrs):
                break

            if pos == 0:
                continue

            insn_addr, insn_size = insn_addrs[pos - 1]

            if insn_addr < label_addr < insn_addr + insn_size:
                # this label should be converted to something like 0x8000040+1
                labels = self.symbol_manager.addr_to_label[label_addr]
                for label in labels:
                    label.base_addr = insn_addrs[pos][0]
                    changed_labels.append(label)

        for label in changed_labels:
            self.symbol_manager.addr_to_label[label.original_addr].remove(label)
            if not self.symbol_manager.addr_to_label[label.original_addr]:
                del self.symbol_manager.addr_to_label[label.original_addr]
            self.symbol_manager.addr_to_label[label.base_addr].append(label)

        if changed_labels:
            for proc in self.procedures:
                proc.assign_labels()

    def assembly(self, comments=False, symbolized=True):

        if symbolized and self._symbolization_needed:
            self.symbolize()

        if self._remove_cgc_attachments:
            self._cgc_attachments_removed = self.remove_cgc_attachments()

        s = ""

        if self.syntax == 'intel':
            s += "\t.intel_syntax noprefix\n"

        all_assembly_lines = [ ]

        addr_and_assembly = [ ]
        for proc in self.procedures:
            addr_and_assembly.extend(proc.assembly(comments=comments, symbolized=symbolized))
        # sort it by the address - must be a stable sort!
        addr_and_assembly = sorted(addr_and_assembly, key=lambda x: x[0] if x[0] is not None else -1)
        all_assembly_lines.extend(line for _, line in addr_and_assembly)

        last_section = None

        if self._cgc_attachments_removed:
            all_data = self.data + self.extra_rodata + self.extra_data
        else:
            # to reduce memory usage, we put extra data in front of the original data in binary
            all_data = self.extra_data + self.data + self.extra_rodata

        for data in all_data:
            if last_section is None or data.section_name != last_section:
                last_section = data.section_name
                all_assembly_lines.append("\t.section {section}\n\t.align {alignment}".format(
                    section=(last_section if last_section != '.init_array' else '.data'),
                    alignment=self.section_alignment(last_section)
                ))
            all_assembly_lines.append(data.assembly(comments=comments, symbolized=symbolized))

        s = "\n".join(all_assembly_lines)

        return s

    def remove_cgc_attachments(self):
        """
        Remove CGC attachments.

        :return: True if CGC attachments are found and removed, False otherwise
        :rtype: bool
        """

        cgc_package_list = None
        cgc_extended_application = None

        for data in self.data:
            if data.sort == 'cgc-package-list':
                cgc_package_list = data
            elif data.sort == 'cgc-extended-application':
                cgc_extended_application = data

        if not cgc_package_list or not cgc_extended_application:
            return False

        if cgc_package_list.skip or cgc_extended_application.skip:
            # they have already been removed
            # so we still return True to indicate that CGC attachments have been removed
            return True

        # there is a single function referencing them
        cgcpl_memory_data = self.cfg.memory_data.get(cgc_package_list.addr, None)
        cgcea_memory_data = self.cfg.memory_data.get(cgc_extended_application.addr, None)
        refs = self.cfg.kb.xrefs

        if cgcpl_memory_data is None or cgcea_memory_data is None:
            return False

        if len(refs.get_xrefs_by_dst(cgcpl_memory_data.addr)) != 1:
            return False
        if len(refs.get_xrefs_by_dst(cgcea_memory_data.addr)) != 1:
            return False

        # check if the irsb addresses are the same
        if next(iter(refs.get_xrefs_by_dst(cgcpl_memory_data.addr))).block_addr != \
                next(iter(refs.get_xrefs_by_dst(cgcea_memory_data.addr))).block_addr:
            return False

        insn_addr = next(iter(refs.get_xrefs_by_dst(cgcpl_memory_data.addr))).ins_addr
        # get the basic block
        cfg_node = self.cfg.model.get_any_node(insn_addr, anyaddr=True)
        if not cfg_node:
            return False

        func_addr = cfg_node.function_address

        # this function should be calling another function
        sub_func_addr = None
        if func_addr not in self.cfg.functions:
            return False
        function = self.cfg.functions[func_addr]
        # traverse the graph and make sure there is only one call edge
        calling_targets = [ ]
        for _, dst, data in function.transition_graph.edges(data=True):
            if 'type' in data and data['type'] == 'call':
                calling_targets.append(dst.addr)

        if len(calling_targets) != 1:
            return False

        sub_func_addr = calling_targets[0]

        # alright. We want to nop this function, as well as the subfunction
        proc = next((p for p in self.procedures if p.addr == func_addr), None)
        if proc is None:
            return False

        subproc = next((p for p in self.procedures if p.addr == sub_func_addr), None)
        if subproc is None:
            return False

        # if those two data entries have any label, we should properly modify them
        # at this point, we are fairly confident that none of those labels are direct data references to either package
        # list or extended application
        has_label = True
        lowest_address = min(cgc_package_list.addr, cgc_extended_application.addr)
        for obj in (cgc_package_list, cgc_extended_application):
            labels = obj.labels
            for addr, label in labels:
                if addr != lowest_address:
                    label.base_addr = lowest_address

        if has_label:
            # is there any memory data entry that ends right at the lowest address?
            data = next((d for d in self.data if d.addr is not None and d.addr + d.size == lowest_address), None)
            if data is None:
                # since there is no gap between memory data entries (we guarantee that), this can only be that no other
                # data resides in the same memory region that CGC attachments are in
                pass
            else:
                lbl = self.symbol_manager.addr_to_label[lowest_address][0]
                if lbl not in data.end_labels:
                    data.end_labels.append(lbl)

        # practically nop the function
        proc.asm_code = "\tret\n"
        subproc.asm_code = "\tret\n"

        # remove those two data entries
        cgc_package_list.skip = True
        cgc_extended_application.skip = True

        l.info('CGC attachments are removed.')

        return True

    def remove_unnecessary_stuff(self):
        """
        Remove unnecessary functions and data

        :return: None
        """

        # determine if the binary is compiled against glibc
        is_glibc = False
        for dep in self.project.loader.main_object.deps:
            if dep.lower() in {'libc.so.6', 'libc.so'}:
                is_glibc = True
                break
        if is_glibc:
            self.remove_unnecessary_stuff_glibc()

    def remove_unnecessary_stuff_glibc(self):
        glibc_functions_blacklist = {
            '_start',
            'init',
            '_init',
            'fini',
            '_fini',
            '__gmon_start__',
            '__do_global_dtors_aux',
            'frame_dummy',
            'atexit',
            'deregister_tm_clones',
            'register_tm_clones',
            '__x86.get_pc_thunk.bx',
            '__libc_csu_init',
            '__libc_csu_fini',
        }

        glibc_data_blacklist = {
            '__TMC_END__',
            '_GLOBAL_OFFSET_TABLE_',
            '__JCR_END__',
            '__dso_handle',
            '__init_array_start',
            '__init_array_end',

            #
            'stdout',
            'stderr',
            'stdin',
            'program_invocation_short_',
            'program_invocation_short_name',
            'program_invocation_name',
            '__progname_full',
            '_IO_stdin_used',
            'obstack_alloc_failed_hand',
            'optind',
            'optarg',
            '__progname',
            '_environ',
            'environ',
            '__environ',
        }

        glibc_references_blacklist = {
            'frame_dummy',
            '__do_global_dtors_aux',
        }

        self.procedures = [p for p in self.procedures if p.name not in glibc_functions_blacklist and not p.is_plt]

        # special handling for _init_proc
        try:
            init_func = self.cfg.functions['init']
            callees = [ node for node in init_func.transition_graph.nodes()
                        if isinstance(node, Function) and node.addr != self.cfg._unresolvable_call_target_addr ]
            # special handling for GCC-generated X86 PIE binaries
            non_getpc_callees = [ callee for callee in callees if 'get_pc' not in callee.info ]
            if len(non_getpc_callees) == 1:
                # we found the _init_proc
                _init_proc = non_getpc_callees[0]
                self.procedures = [p for p in self.procedures if p.addr != _init_proc.addr]
        except KeyError:
            pass

        self.data = [d for d in self.data if not any(lbl.name in glibc_data_blacklist for _, lbl in d.labels)]

        for d in self.data:
            if d.sort == MemoryDataSort.PointerArray:
                for i in range(len(d.content)):
                    ptr = d.content[i]
                    if isinstance(ptr, Label) and ptr.name in glibc_references_blacklist:
                        d.content[i] = 0
            elif d.sort == MemoryDataSort.SegmentBoundary:
                if d.labels:
                    new_labels = [ ]
                    for rebased_addr, label in d.labels:
                        # check if this label belongs to a removed function
                        if self.cfg.functions.contains_addr(rebased_addr) and \
                                self.cfg.functions[rebased_addr].name in glibc_functions_blacklist:
                            # we need to remove this label...
                            continue
                        else:
                            new_labels.append((rebased_addr, label))
                    d.labels = new_labels

    #
    # Private methods
    #

    def _initialize(self):
        """
        Initialize the binary.

        :return: None
        """

        # figure out section alignments
        for section in self.project.loader.main_object.sections:
            in_segment = False
            for segment in self.project.loader.main_object.segments:
                segment_addr = segment.vaddr
                if segment_addr <= section.vaddr < segment_addr + segment.memsize:
                    in_segment = True
                    break
            if not in_segment:
                continue

            # calculate alignments
            if section.vaddr % 0x20 == 0:
                alignment = 0x20
            elif section.vaddr % 0x10 == 0:
                alignment = 0x10
            elif section.vaddr % 0x8 == 0:
                alignment = 0x8
            elif section.vaddr % 0x4 == 0:
                alignment = 0x4
            else:
                alignment = 2

            self._section_alignments[section.name] = alignment

        l.debug('Generating CFG...')
        cfg = self.project.analyses[CFGFast].prep()(normalize=True, resolve_indirect_jumps=True, data_references=True,
                                        extra_memory_regions=[(0x4347c000, 0x4347c000 + 0x1000)],
                                        data_type_guessing_handlers=[
                                            self._sequence_handler,
                                            self._cgc_extended_application_handler,
                                            self._unknown_data_size_handler,
                                        ],
                                        )

        self.cfg = cfg

        old_capstone_syntax = self.project.arch.capstone_x86_syntax
        if old_capstone_syntax is None:
            old_capstone_syntax = 'intel'

        if self.syntax == 'at&t':
            # switch capstone to AT&T style
            self.project.arch.capstone_x86_syntax = "at&t"
            # clear the block cache in lifter!
            self.project.factory.default_engine.clear_cache()

        # initialize symbol manager
        self.symbol_manager = SymbolManager(self, cfg)

        # collect address of all instructions
        l.debug('Collecting instruction addresses...')
        for cfg_node in self.cfg.nodes():
            self.all_insn_addrs |= set(cfg_node.instruction_addrs)

        # Functions

        l.debug('Creating functions...')
        for f in cfg.kb.functions.values():
            # Skip all SimProcedures
            if self.project.is_hooked(f.addr):
                continue
            elif self.project.simos.is_syscall_addr(f.addr):
                continue

            # Check which section the start address belongs to
            section = next(iter(sec.name for sec in self.project.loader.main_object.sections
                                if f.addr >= sec.vaddr and f.addr < sec.vaddr + sec.memsize
                                ),
                           ".text"
                           )

            if section in {'.got', '.plt', 'init', 'fini', '.init', '.fini'}:
                continue

            procedure = Procedure(self, function=f, section=section)
            self.procedures.append(procedure)

        self.procedures = sorted(self.procedures, key=lambda x: x.addr)

        # Data

        has_sections = len(self.project.loader.main_object.sections) > 0

        l.debug('Creating data entries...')
        for addr, memory_data in cfg._memory_data.items():

            if memory_data.sort in ('code reference', ):
                continue

            if memory_data.sort == 'string':
                # it might be the CGC package list
                new_sort, new_size = self._cgc_package_list_identifier(memory_data.address, memory_data.size)
                if new_sort is not None:
                    # oh we got it!
                    memory_data = memory_data.copy()
                    memory_data.sort = new_sort

            if has_sections:
                # Check which section the start address belongs to
                section = next(iter(sec for sec in self.project.loader.main_object.sections
                                    if sec.vaddr <= addr < sec.vaddr + sec.memsize
                                    ),
                               None
                               )

                if section is not None and section.name not in ('.note.gnu.build-id', ):  # ignore certain section names
                    data = Data(self, memory_data, section=section)
                    self.data.append(data)
                elif memory_data.sort == 'segment-boundary':
                    # it just points to the end of the segment or a section
                    section = next(iter(sec for sec in self.project.loader.main_object.sections
                                        if addr == sec.vaddr + sec.memsize),
                                   None
                                   )
                    if section is not None:
                        data = Data(self, memory_data, section=section)
                        self.data.append(data)

                else:
                    # data = Data(self, memory_data, section_name='.data')
                    # the data is not really within any existing section. weird. ignored it.
                    pass
            else:
                # the binary does not have any section
                # we use segment information instead
                # TODO: this logic needs reviewing
                segment = next(iter(seg for seg in self.project.loader.main_object.segments
                                    if seg.vaddr <= addr <= seg.vaddr + seg.memsize
                                    ),
                               None
                               )

                if segment is not None:
                    data = Data(self, memory_data, section_name='.data')
                    self.data.append(data)

        # remove all data that belong to GCC-specific sections
        section_names_to_ignore = {'.init', '.fini', '.fini_array', '.jcr', '.dynamic', '.got', '.got.plt',
                                   '.eh_frame_hdr', '.eh_frame', '.rel.dyn', '.rel.plt', '.rela.dyn', '.rela.plt',
                                   '.dynstr', '.dynsym', '.interp', '.note.ABI-tag', '.note.gnu.build-id', '.gnu.hash',
                                   '.gnu.version', '.gnu.version_r'
                                   }

        # make sure there are always memory data entries pointing at the end of sections
        all_data_addrs = set(d.addr for d in self.data)
        all_procedure_addrs = set(f.addr for f in self.procedures)
        all_addrs = all_data_addrs | all_procedure_addrs

        if has_sections:
            for section in self.project.loader.main_object.sections:

                if section.name in section_names_to_ignore:
                    # skip all sections that are CGC specific
                    continue

                # make sure this section is not empty
                if section.memsize == 0:
                    continue

                # make sure this section is inside a segment
                for segment in self.project.loader.main_object.segments:
                    segment_start = segment.vaddr
                    segment_end = segment_start + segment.memsize
                    if segment_start <= section.vaddr < segment_end:
                        break
                else:
                    # this section is not mapped into memory
                    continue

                section_boundary_addr = section.vaddr + section.memsize
                if section_boundary_addr not in all_addrs:
                    data = Data(self, addr=section_boundary_addr, size=0, sort='segment-boundary',
                                section_name=section.name
                                )
                    self.data.append(data)
                    # add the address to all_data_addrs so we don't end up adding another boundary in
                    all_data_addrs.add(section_boundary_addr)

        self.data = sorted(self.data, key=lambda x: x.addr)

        data_indices_to_remove = set()

        # Go through data entry list and refine them
        for i, data in enumerate(self.data):

            if i in data_indices_to_remove:
                continue

            # process the overlapping ones
            if i < len(self.data) - 1:
                if data.addr + data.size > self.data[i + 1].addr:
                    # they are overlapping :-(

                    # TODO: make sure new_size makes sense
                    new_size = self.data[i + 1].addr - data.addr

                    # there are cases that legit data is misclassified as pointers
                    # we are able to detect some of them here
                    if data.sort == 'pointer-array':
                        pointer_size = self.project.arch.bytes
                        if new_size % pointer_size != 0:
                            # the self.data[i+1] cannot be pointed to by a pointer
                            # remove that guy later
                            data_indices_to_remove.add(i + 1)
                            # mark the source as a non-pointer
                            # apparently the original Reassembleable Disassembler paper cannot get this case
                            source_addr = self.data[i + 1].memory_data.pointer_addr
                            if source_addr is not None:
                                # find the original data
                                original_data = next((d for d in self.data if d.addr <= source_addr < d.addr + d.size),
                                                     None
                                                     )
                                if original_data is not None:
                                    original_data.desymbolize()

                            continue

                    data.shrink(new_size)

            # process those ones whose type is unknown
            if data.sort == 'unknown' and data.size == 0:
                # increase its size until reaching the next item

                if i + 1 == len(self.data):
                    if data.section is None:
                        continue
                    data.size = data.section.vaddr + data.section.memsize - data.addr
                else:
                    data.size = self.data[i + 1].addr - data.addr

        for i in sorted(data_indices_to_remove, reverse=True):
            self.data = self.data[ : i] + self.data[i + 1 : ]

        # CGC-specific data filtering
        self.data = [ d for d in self.data if d.section_name not in section_names_to_ignore ]

        # restore capstone X86 syntax at the end
        if self.project.arch.capstone_x86_syntax != old_capstone_syntax:
            self.project.arch.capstone_x86_syntax = old_capstone_syntax
            self.project.factory.default_engine.clear_cache()

        l.debug('Initialized.')

    def _is_sequence(self, cfg, addr, size):
        data = self.fast_memory_load(addr, size, bytes)
        if data is None:
            return False
        ints = [i for i in data]
        if len(set([(i - j) for i, j in zip(ints, ints[1:])])) == 1:
            # arithmetic progression
            # backoff: it should not be ending with a pointer
            closest_aligned_addr = (addr + size - 1) & 0xfffffffc
            ptr = self.fast_memory_load(closest_aligned_addr, 4, int, endness=self.project.arch.memory_endness)
            if ptr is None:
                return False
            if self._is_pointer(cfg, ptr):
                return False
            return True
        return False

    @staticmethod
    def _is_pointer(cfg, ptr):
        if cfg.project.loader.find_section_containing(ptr) is not None or \
                cfg.project.loader.find_segment_containing(ptr) is not None or \
                (cfg._extra_memory_regions and
                     next(((a < ptr < b) for (a, b) in cfg._extra_memory_regions), None)
                 ):
            return True
        return False

    def _sequence_handler(self, cfg, irsb, irsb_addr, stmt_idx, data_addr, max_size):  # pylint:disable=unused-argument
        """
        Find sequences in binary data.

        :param angr.analyses.CFG cfg: The control flow graph.
        :param pyvex.IRSB irsb: The IRSB object.
        :param int irsb_addr: Address of the block.
        :param int stmt_idx: Statement ID.
        :param int data_addr: Address of the data in memory.
        :param int max_size: Maximum size possible.
        :return: A 2-tuple of data type and size.
        :rtype: tuple
        """

        if not self._is_sequence(cfg, data_addr, 5):
            # fail-fast
            return None, None

        sequence_max_size = min(256, max_size)

        for i in range(5, min(256, max_size)):
            if not self._is_sequence(cfg, data_addr, i):
                return 'sequence', i - 1

        return 'sequence', sequence_max_size

    def _cgc_package_list_identifier(self, data_addr, data_size):
        """
        Identifies the CGC package list associated with the CGC binary.

        :param int data_addr: Address of the data in memory.
        :param int data_size: Maximum size possible.
        :return: A 2-tuple of data type and size.
        :rtype: tuple
        """

        if data_size < 100:
            return None, None

        data = self.fast_memory_load(data_addr, data_size, str)

        if data[:10] != 'The DECREE':
            return None, None

        if not all(i in string.printable for i in data):
            return None, None

        if not re.match(r"The DECREE packages used in the creation of this challenge binary were:", data):
            return None, None

        return 'cgc-package-list', data_size

    def _cgc_extended_application_handler(self, cfg, irsb, irsb_addr, stmt_idx, data_addr, max_size):  # pylint:disable=unused-argument
        """
        Identifies the extended application (a PDF file) associated with the CGC binary.

        :param angr.analyses.CFG cfg: The control flow graph.
        :param pyvex.IRSB irsb: The IRSB object.
        :param int irsb_addr: Address of the block.
        :param int stmt_idx: Statement ID.
        :param int data_addr: Address of the data in memory.
        :param int max_size: Maximum size possible.
        :return: A 2-tuple of data type and size.
        :rtype: tuple
        """

        if max_size < 100:
            return None, None

        data = self.fast_memory_load(data_addr, 20, bytes)

        if data is not None and data[:4] != b'The ':
            return None, None

        # read everything in
        data = self.fast_memory_load(data_addr, max_size, str)

        m = re.match(r"The ([\d]+) byte CGC Extended Application follows.", data)
        if not m:
            return None, None
        pdf_size = int(m.group(1))

        if '%PDF' not in data:
            return None, None
        if '%%EOF' not in data:
            return None, None

        pdf_data = data[data.index('%PDF') : data.index('%%EOF') + 6]

        if len(pdf_data) != pdf_size:
            return None, None

        return 'cgc-extended-application', max_size

    def _unknown_data_size_handler(self, cfg, irsb, irsb_addr, stmt_idx, data_addr, max_size):  # pylint:disable=unused-argument
        """
        Return the maximum number of bytes until a potential pointer or a potential sequence is found.

        :param angr.analyses.CFG cfg: The control flow graph.
        :param pyvex.IRSB irsb: The IRSB object.
        :param int irsb_addr: Address of the block.
        :param int stmt_idx: Statement ID.
        :param int data_addr: Address of the data in memory.
        :param int max_size: Maximum size possible.
        :return: A 2-tuple of data type and size.
        :rtype: tuple
        """

        sequence_offset = None

        for offset in range(1, max_size):
            if self._is_sequence(cfg, data_addr + offset, 5):
                # a potential sequence is found
                sequence_offset = offset
                break

        if sequence_offset is not None:
            if self.project.arch.bits == 32:
                max_size = min(max_size, sequence_offset)
            elif self.project.arch.bits == 64:
                max_size = min(max_size, sequence_offset + 5)  # high 5 bytes might be all zeros...

        ptr_size = cfg.project.arch.bytes

        size = None

        for offset in range(1, max_size - ptr_size + 1):
            ptr = self.fast_memory_load(data_addr + offset, ptr_size, int, endness=cfg.project.arch.memory_endness)
            if self._is_pointer(cfg, ptr):
                size = offset
                break

        if size is not None:
            return "unknown", size
        elif sequence_offset is not None:
            return "unknown", sequence_offset
        else:
            return None, None

    def _has_integer_used_as_pointers(self):
        """
        Test if there is any (suspicious) pointer decryption in the code.

        :return: True if there is any pointer decryption, False otherwise.
        :rtype: bool
        """

        # check all integer accesses and see if there is any integer being used as a pointer later, but it wasn't
        # classified as a pointer reference

        # we only care about unknown memory data that are 4 bytes long, and is directly referenced from an IRSB
        candidates = [ i for i in self.cfg.memory_data.values() if
                       i.sort in ('unknown', 'integer') and
                       i.size == self.project.arch.bytes and
                       i.irsb_addr is not None
                       ]

        if not candidates:
            return False

        for candidate in candidates:

            # if the candidate is in .bss, we don't care about it
            sec = self.cfg.project.loader.find_section_containing(candidate.address)
            if sec.name in ('.bss', '.got.plt'):
                continue

            # execute the single basic block and see how the value is used
            base_graph = networkx.DiGraph()
            candidate_node = self.cfg.model.get_any_node(candidate.irsb_addr)  # type: angr.analyses.cfg_node.CFGNode
            if candidate_node is None:
                continue
            base_graph.add_node(candidate_node)
            tmp_kb = KnowledgeBase(self.project)
            cfg = self.project.analyses[CFGEmulated].prep(kb=tmp_kb)(
                                                    starts=(candidate.irsb_addr,),
                                                    keep_state=True,
                                                    base_graph=base_graph
                                                    )
            candidate_irsb = cfg.get_any_irsb(candidate.irsb_addr)  # type: SimIRSB
            ddg = self.project.analyses[DDG].prep(kb=tmp_kb)(cfg=cfg)

            mem_var_node = None
            for node in ddg.simplified_data_graph.nodes():
                if isinstance(node.variable, SimMemoryVariable) and node.location.ins_addr == candidate.insn_addr:
                    # found it!
                    mem_var_node = node
                    break
            else:
                # mem_var_node is not found
                continue

            # get a sub graph
            subgraph = ddg.data_sub_graph(mem_var_node,
                                          simplified=False,
                                          killing_edges=False,
                                          excluding_types={'mem_addr'},
                                          )

            # is it used as a memory address anywhere?
            # TODO:

            # is it used as a jump target?
            next_tmp = None
            if isinstance(candidate_irsb.irsb.next, pyvex.IRExpr.RdTmp):
                next_tmp = candidate_irsb.irsb.next.tmp

            if next_tmp is not None:
                next_tmp_node = next((node for node in subgraph.nodes()
                                      if isinstance(node.variable, SimTemporaryVariable) and
                                         node.variable.tmp_id == next_tmp),
                                     None
                                     )
                if next_tmp_node is not None:
                    # ouch it's used as a jump target
                    return True

        return False

    def fast_memory_load(self, addr, size, data_type, endness='Iend_LE'):
        """
        Load memory bytes from loader's memory backend.

        :param int addr:    The address to begin memory loading.
        :param int size:    Size in bytes.
        :param data_type:   Type of the data.
        :param str endness: Endianness of this memory load.
        :return:            Data read out of the memory.
        :rtype:             int or bytes or str or None
        """

        if data_type is int:
            try:
                return self.project.loader.memory.unpack_word(addr, size=size, endness=endness)
            except KeyError:
                return None

        try:
            data = self.project.loader.memory.load(addr, size)
            if data_type is str:
                return "".join(chr(i) for i in data)
            return data
        except KeyError:
            return None


from angr.analyses import AnalysesHub
AnalysesHub.register_default('Reassembler', Reassembler)
