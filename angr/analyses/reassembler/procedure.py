import pdb
import logging
from .block import BasicBlock
from .labels import FunctionLabel
from .ramblr_errors import BinaryError, InstructionError, ReassemblerFailureNotice

l = logging.getLogger("angr.analyses.reassembler")

class Procedure(object):
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
        l.warning("Deprecated call to proc.assembly, use assemble_proc")
        return self.assemble_proc(comments, symbolized)

    def assemble_proc(self, comments=False, symbolized=True):
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

            if function_label == "_start" and self.project.extract_libc_main and self.project.arch.name == "ARMEL":
                # If this is a libc binary, extract main from _start and don't output _start at all, assembler can do that for us, better
                #return ""
                pass

            header += str(function_label) + "\n"

        assembly.append((self.addr, header))

        if self.asm_code:
            s = self.asm_code
            assembly.append((self.addr, s))
        elif self.blocks:
            for b in sorted(self.blocks, key=lambda x:x.addr):  # type: BasicBlock
                s = b.assemble_block(comments=comments, symbolized=symbolized)
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
            for block_addr in self.function.block_addrs:
                b = BasicBlock(self.binary, block_addr, self.function._block_sizes[block_addr])
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

