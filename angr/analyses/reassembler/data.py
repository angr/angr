import pdb # TODO: debug only

import logging
import re
import struct
from collections import defaultdict
import string
import capstone
import cffi
import networkx
import pyvex
from .. import Analysis, register_analysis

from ...knowledge_base import KnowledgeBase
from ...sim_variable import SimMemoryVariable, SimTemporaryVariable
from ..cfg  import CFGArchOptions

from .ramblr_utils import string_escape, ignore_function
from .labels import Label, DataLabel, FunctionLabel, ObjectLabel, NotypeLabel
from .symbol_manager import SymbolManager
#from .procedure import Procedure, ProcedureChunk
from .ramblr_errors import BinaryError, InstructionError, ReassemblerFailureNotice

l = logging.getLogger("angr.analyses.reassembler")
l.setLevel("WARNING")

class Data(object):
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

        if self.sort == 'string':
            self.null_terminated = False # string without the null byte terminator
            self._content[0] = self._content[0][ : self.size]

        elif self.sort == 'pointer-array':
            pointer_size = self.binary.project.arch.bits / 8

            if self.size % pointer_size != 0:
                # it's not aligned?
                raise BinaryError('Fails at Data.shrink()')

            pointers = self.size / pointer_size
            self._content = self._content[ : pointers]

        else:
            # unknown
            if self._content:
                self._content =  [ self._content[0][ : self.size ] ]
            else:
                return None

    def desymbolize(self):
        """
        We believe this was a pointer and symbolized it before. Now we want to desymbolize it.

        The following actions are performed:
        - Reload content from memory
        - Mark the sort as 'unknown'

        :return: None
        """

        self.sort = 'unknown'
        content = self.binary.fast_memory_load(self.addr, self.size, str)
        self.content = [ content ]

    def assign_labels(self):

        # TODO: What if it's not aligned for some sort of data, like pointer array?

        if self.addr is None:
            # this piece of data comes from a patch, not from the original binary
            return

        # Put labels to self.labels
        for i in xrange(self.size):
            addr = self.addr + i
            if addr in self.binary.symbol_manager.addr_to_label:
                labels = self.binary.symbol_manager.addr_to_label[addr]

                for label in labels:
                    if self.sort == 'pointer-array' and addr % (self.project.arch.bits / 8) != 0:
                        # we need to modify the base address of the label
                        base_addr = addr - (addr % (self.project.arch.bits / 8))
                        label.base_addr = base_addr
                        tpl = (base_addr, label)
                        if tpl not in self.labels:
                            #l.info("Assign labels: {} = 0x{:x}".format(label.name, addr))
                            self.labels.append(tpl)
                    else:
                        tpl = (addr, label)
                        if tpl not in self.labels:
                            #l.info("Assign labels: {} = 0x{:x}".format(label.name, addr))
                            self.labels.append(tpl)

    def assembly(self, comments=False, symbolized=True):
        l.warning("Deprecated call to data.assembly. Use data.data_assembly")
        return self.data_assembly(comments, symbolized)

    def data_assembly(self, comments=False, symbolized=True):
        s = ""
        blacklisted_labels = ["__JCR_END__"] # Named values we skip printing
        if comments:
            # TODO: move comments so they're after each label/section header
            if self.addr is not None:
                s += "\t# data @ %#08x\n" % self.addr
            else:
                s += "\t# data (%s)\n" % self.name

        # Can we skip unlabeled values? This often picks up null terminators after strings. Disabling for now
        #if symbolized and not self.labels:
        #    s += "\t# SKIP?\n"

        if self.skip:
            return s

        if self.sort == 'unknown':
            l.warning("Trying to assemble 0x{:x} but we still don't know what it's sort is".format(self.addr))

        if self.sort == 'string':

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

        elif self.sort == 'pointer-array':

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

                if len(self.content) == 0:
                    if self.addr is not None and (self.addr + i) in addr_to_labels:
                        for label in addr_to_labels[self.addr + i]:
                            s += "%s\n" % str(label)
                    elif self.addr is not None and (self.addr + i) in self.binary.symbol_manager.addr_to_label:
                        labels = self.binary.symbol_manager.addr_to_label[self.addr + i]
                        for label in labels:
                            s += "%s\n" % str(label)

                    l.warning("No content in pointer array[0x{:x}] for {} defining as 0".format(self.addr, s.split("\n")[-2]))
                    s+= "\t# WARNING: unknown value - set to 0\n"
                    s+= "\t.byte 0\n"
                for symbolized_label in self.content:

                    if self.addr is not None and (self.addr + i) in addr_to_labels:
                        for label in addr_to_labels[self.addr + i]:
                            s += "%s\n" % str(label)
                    elif self.addr is not None and (self.addr + i) in self.binary.symbol_manager.addr_to_label:
                        labels = self.binary.symbol_manager.addr_to_label[self.addr + i]
                        for label in labels:
                            s += "%s\n" % str(label)
                    i += self.project.arch.bits / 8
                    if symbolized_label is None:
                        l.warning("Empty value in content for pointer array[0x{:x}] with labels: {} defining as 0".format(self.addr, s.split("\n")[-2]))
                        s+= "\t# WARNING: unknown value - set to 0\n"
                        s+= "\t.byte 0\n"
                        continue

                    if isinstance(symbolized_label, (int, long)):
                        s += "\t%s %d\n" % (directive, symbolized_label)
                    else:
                        if symbolized_label.operand_str in blacklisted_labels:
                            s += "\t# Blacklisted label %s ignored" % (symbolized_label.operand_str)
                            continue
                        s += "\t%s %s\n" % (directive, symbolized_label.operand_str)

            else:
                for label in self.content:
                    s += "\t%s %s\n" % (directive, label.operand_str)

        elif self.sort == 'segment-boundary':

            if symbolized:
                for _, label in self.labels:
                    s += "\t%s\n" % str(label)

        elif self.sort == 'integer':
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
                    if self.addr is not None and addr_to_labels.keys()[0] == self.addr:
                        show_integer = True
                    elif self.addr is None and addr_to_labels.keys()[0] == 0:
                        show_integer = True

                if directive is not None and show_integer:
                    # nice, we should display it as an integer
                    if addr_to_labels:
                        for label in addr_to_labels.values()[0]:
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
                        if not piece:
                            l.warning("Could not render content at 0x{:x}".format(self.addr))
                        for c in piece:
                            if addr in addr_to_labels:
                                for label in addr_to_labels[addr]:
                                    content += [ "%s" % str(label) ]
                            addr += 1

                            content += ['\t.byte %d' % ord(c)]

            else:
                integer = struct.unpack(fmt_str, self.content[0])[0]
                content += ['\t{directive} {integer}'.format(
                    directive=directive,
                    integer='%#x' % integer,
                )]

            s += "\n".join(content)
            s += "\n"

        elif self.sort == 'fp':
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

                        content += ['\t.byte %d' % ord(c)]
            else:
                for piece in self.content:
                    content += ['\t.byte %d' % ord(c) for c in piece]

            s += "\n".join(content)
            s += "\n"

        else:
            content = []
            if self.sort == None:
                l.debug("Data sort is none at 0x%x (%s)", self.addr, ", ".join([x.name for _, x in self.labels]))

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

                        content += ['\t.byte %d' % ord(c)]

                # Something bad is going on, we've created a label but don't know what data to place here
                if not len(self.content):
                    if addr in addr_to_labels:
                        #l.warning("Empty content for label(s) %s at addr 0x%x", ", ".join([x.name for x in addr_to_labels[addr]]), addr)

                        for label in addr_to_labels[addr]:
                            content += ["%s" % str(label) , "\t#Unknown data (This should never happen)"]
                        for _ in range((self.size / self.project.arch.bits)*4): # How many bytes in this size
                            content += ["\t.byte 0"]
            else:
                for piece in self.content:
                    content += [ '\t.byte %d' % ord(c) for c in piece ]

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


            if self.sort == 'pointer-array':

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

                for i in xrange(0, len(self._initial_content), pointer_size):
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

            elif self.sort in ('string', 'unknown', 'integer'):

                lbl = DataLabel(self.binary, -1, name=self.name)
                self.labels.append((0, lbl))

                self._content = [ self._initial_content ]
                l.warning("Initialized _content at 0x%x with %s", self.addr, str(self._content))

            elif self.sort == 'segment-boundary':
                label = self.binary.symbol_manager.new_label(self.addr)
                self.labels.append((self.addr, label))
                self._content = []

            else:
                raise BinaryError('Unsupported data sort "%s"' % self.sort)

        else:
            self.addr = self.memory_data.address
            self.size = self.memory_data.size
            self.sort = self.memory_data.sort

            if not self.size:
                # Fixed size architectures in capstone don't have .size
                if self.binary.project.arch.name in ['PPC32', 'ARMEL', 'MIPS32']:
                    self.size = 32
                else:
                    raise RuntimeError("Size is undefined for {} {}".format(self.binary.project.arch.name, self.memory_data))

            # Symbolize the content
            if self.sort == 'pointer-array':
                # read out the address
                pointer_size = self.project.arch.bits / 8
                pointers = self.size / pointer_size

                self._content = []
                for i in xrange(pointers):
                    addr = self.binary.fast_memory_load(self.addr + i * pointer_size, pointer_size, int,
                                                        endness=self.project.arch.memory_endness
                                                        )
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

            elif self.sort == 'string':
                data = self.binary.fast_memory_load(self.addr, self.size, str)
                if data[-1] == '\0':
                    self.null_terminated = True
                    data = data[:-1] # remove the null-byte. we'll use .asciz for it instead.
                else:
                    self.null_terminated = False

                self._content = [data]

            elif self.sort == 'integer':
                data = self.binary.fast_memory_load(self.addr, self.size, str)
                self._content = [ data ]

            elif self.sort == 'segment-boundary':
                label = self.binary.symbol_manager.new_label(self.addr)
                self.labels.append((self.addr, label))

                self._content = [ ]

            elif self.sort == 'fp':
                # floating-point integers
                # Python has some trouble in dealing with floating point numbers
                # just store them as bytes
                data = self.binary.fast_memory_load(self.addr, self.size, str)
                self._content = [ data ]

            else:
                # other sorts
                content = self.binary.fast_memory_load(self.addr, self.size, str)
                if content is not None:
                    self._content = [content]
                else:
                    self._content = []


