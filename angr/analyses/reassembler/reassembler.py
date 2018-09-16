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
from .procedure import Procedure, ProcedureChunk
from .data import Data
from .ramblr_errors import BinaryError, InstructionError, ReassemblerFailureNotice

l = logging.getLogger("angr.analyses.reassembler")
l.setLevel("WARNING")

class Relocation(object):
    def __init__(self, addr, ref_addr, sort):
        self.addr = addr
        self.ref_addr = ref_addr
        self.sort = sort

    def __repr__(self):
        s = "<Reloc %s %#x (%#x)>" % (self.sort, self.addr, self.ref_addr)
        return s

"""
# Debug-only helper class to replace arrays so we can trigger breakpoints when elements are added
class FakeList(list):
    def __init__(self, name):
        self.data = []
        self.name = name

    def __getitem__(self,x):
        #print('GET {:x}'.format(x))
        return self.data[x]

    def __setitem__(self,x,y):
        print('set {}={}'.format(x,y))
        self.data[x] =y

    def append(self,x):
        self.data.append(x)

    def __iter__(self):
        return super(FakeList, self).__iter__()

    def __contains__(self,x):
        return super(FakeList, self).__contains__(x)
"""


class Reassembler(Analysis):
    """
    High-level representation of a binary with a linear representation of all instructions and data regions. After
    calling "symbolize", it essentially acts as a binary reassembler.

    Tested on CGC, x86 and x86-64 binaries.

    Discliamer: The reassembler is an empirical solution. Don't be surprised if it does not work on some binaries.
    """
    def __init__(self, syntax="intel", remove_cgc_attachments=True, log_relocations=True, extract_libc_main=True):

        self.syntax = syntax
        self._remove_cgc_attachments = remove_cgc_attachments

        self.symbol_manager = None
        self.cfg = None
        self._cgc_attachments_removed = False
        self.log_relocations = log_relocations

        self.procedures = []
        self.data = []

        self.extra_rodata = [ ]
        self.extra_data = [ ]

        self._main_executable_regions = None
        self._main_nonexecutable_regions = None

        self._symbolization_needed = True

        self._ffi = cffi.FFI()

        # section names to alignments
        self._section_alignments = {}

        # all instruction addresses
        self.all_insn_addrs = set()

        self._relocations = [ ]

        self._inserted_asm_before_label = defaultdict(list)
        self._inserted_asm_after_label = defaultdict(list)
        self._removed_instructions = set()


# TODO: could this be exposed as a better option somewhere else?
# Determines if we search for main when we see a call to __libc_start_main
# If we find one, we can ignore _start and just create main
# When we reassemble, we'll need gcc to use its own _start function and call into our main
# We won't generate .init in this case either

        self.project.extract_libc_main = extract_libc_main

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

        if self.project.arch.name in ["ARMEL"]: # Also MIPS or PPC
            return 4

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

    def register_instruction_reference(self, insn_addr, ref_addr, sort, insn_size, arch=None):
        # Function called when we see an IP-modifying instruction

        # This function is confusing. I think its logic is to:
        #   1) If it's a jump or a call just increment addr so we do something with Relocation()
        #   2) If it's an absolute reference:
        #       3) For each possible sequence of bytes:
        #           4) try to extract the target address


        if not self.log_relocations:
            return

        # For arm, it's an SP relative offset from PC and we don't have to find it, just trust insn_addr
        if arch == "ARMEL":
            r = Relocation(insn_addr, ref_addr, sort)
            self._relocations.append(r)
            #self.register_data_reference(self.addr, insn_addr) #?
            return

        addr = insn_addr
        if sort == 'jump':
            addr += 1
        elif sort == 'call':
            addr += 1
        elif sort == 'absolute':
            # detect it...
            ptr_size = self.project.arch.bits / 8
            for i in xrange(0, insn_size):
                # an absolute address is used
                if insn_size - i >= ptr_size:
                    ptr = self.fast_memory_load(insn_addr + i, ptr_size, int, endness='Iend_LE')
                    if ptr == ref_addr:
                        addr += i
                        break

                # an absolute address of 4 bytes is used
                # e.g. AMD64:
                #      mov r8, offset 0x400070
                #      49 c7 c0 xx xx xx xx
                if ptr_size == 8 and insn_size - i >= 4:
                    ptr = self.fast_memory_load(insn_addr + i, 4, int, endness='Iend_LE')
                    if ptr == ref_addr:
                        addr += i
                        break

                # an relative offset is used, and size of the offset is 4
                # e.g. AMD64:
                #      mov rax, 0x600100
                #      48 8b 05 xx xx xx
                if insn_size - i >= 4:
                    ptr = self.fast_memory_load(insn_addr + i, 4, int, endness='Iend_LE')
                    if (ptr + insn_addr + insn_size) == ref_addr:
                        addr += i
                        break

                # TODO - for ppc32 - what's going on here? Do we just need movs or branches too?
                # Doesnt' seem to matter for now, may need to implement later
                #      bl funcname_10000750
                #      48 00 04 49
            else:
                l.warning('Cannot find the absolute address inside instruction at %#x. Use the default address.',
                          insn_addr)

        else:
            raise BinaryError('Unsupported sort "%s" in register_instruction_reference().' % sort)

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

        lbl = self.symbol_manager.new_label(addr, name=name, force=True)

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

    def append_data(self, name, initial_content, size, readonly=False, sort='unknown'):  # pylint:disable=unused-argument
        """
        Append a new data entry into the binary with specific name, content, and size.

        :param str name: Name of the data entry. Will be used as the label.
        :param str initial_content: The initial content of the data entry.
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
            initial_content = ""

        if type(initial_content) in (int, long):
            initial_content = struct.pack("<I", initial_content)

        initial_content = initial_content.ljust(size, "\x00")

        l.warning("Add data with content {}".format(initial_content))
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

        # If something is defined in both data and proc, say it's just data and remove from procs
        bad_procs=set([x.addr for x in self.data]).intersection(set([x.addr for x in self.procedures]))
        if len(bad_procs):
            l.error("Memory defined as both proc and data at {}. Creating assembly for both".format([hex(x) for x in bad_procs]))
            #l.warning("Memory defined as both proc and data at {}. Treating as data".format([hex(x) for x in bad_procs]))
        #self.procedures[:] = [x for x in self.procedures if x.addr not in bad_procs]

        for proc in self.procedures:
            proc.assign_labels()

        for data in self.data:
            #print("Assign labels to {}".format(data))
            data.assign_labels()
            #print(", ".join([x.name for _, x in data.labels]))
        #print("All labels: {}".format([[y.name for addr, y in x.labels] for x in self.data]))


        # Get all instruction addresses, and modify those labels pointing to the middle of an instruction
        insn_addrs =  [ ]
        for proc in self.procedures:  # type: Procedure
            insn_addrs.extend(proc.instruction_addresses())
        # just to be safe
        insn_addrs = sorted(set(insn_addrs), key=lambda x: x[0])
        #self.cfg._post_analysis() # Rerun TODO - do we need to do this here? related to operand.py changes

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
            #if not self.symbol_manager.addr_to_label[label.original_addr]:
            #    del self.symbol_manager.addr_to_label[label.original_addr]
            #print("Add label {} at a2l[0x{:x}]".format(label.name, label.base_addr))
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

        # TODO: Clean this code up!
        if self.project.extract_libc_main:
            for proc in self.procedures:
                if ignore_function(proc):
                    continue
                if not proc._output_function_label or not proc.addr:
                    continue

                function_label = proc.binary.symbol_manager.new_label(proc.addr)
                if  function_label == "_start": # TODO? Is it working better without this?
                    self.project.extract_libc_main = False # Change back to true only if we succeed
                    insns = proc.blocks[0].instructions
                    asm = []
                    for insn in insns:
                        asm.append(insn.assemble_insn(comments=False, symbolized=True))

                    if not (asm[-1].split("\t")[2] == "__libc_start_main"):
                        continue
                    # Find the last time r0 was set before the libc_start_main call (TODO: sort?)
                    main_lbl = None
                    for insn in asm:
                        if len(insn.split("\t")) < 2:
                            continue

                        op = insn.split("\t")[1]
                        if op != u"ldr":
                            continue

                        if len(insn.split("\t")[2].split(",")) != 2:
                            continue # For ops like ldr     r1, [sp], #4

                        reg, lbl = insn.split("\t")[2].split(",")
                        if reg == "r0":
                            main_lbl = lbl

                    if not main_lbl:
                        continue

                    if "." in main_lbl:
                        main_lbl = main_lbl.split(".")[-1]
                    if "=" in main_lbl:
                        main_lbl = main_lbl.split("=")[-1]

                    if not main_lbl:
                        l.warning("Unable to find call from _start to main")
                        continue
                    self.project.extract_libc_main = True

                    main_addr = proc.binary.symbol_manager.label_to_addr(main_lbl)

                    if not main_addr:
                        l.warning("Could not find main address")
                        continue

                    # Just rename the label to 'main'
                    #TODO maybe we need to create a new procedure at main_addr
                    if len(self.symbol_manager.addr_to_label[main_addr]):
                        self.symbol_manager.addr_to_label[main_addr][0].name = "main"

                    main_lbl_real = proc.binary.symbol_manager.new_label(main_addr, name="main", is_function=True)
                    self.symbol_manager.addr_to_label[main_addr].append(main_lbl_real)

                    # Figure out if we're in an existing procedure
                    proc = next((p for p in self.procedures if main_addr in [x[0] for x in p.instruction_addresses()]), None)
                    if proc is None:
                        l.warning("Couldn't find main (0x%x) in existing proc", main_addr)
                    else:
                        pass

        for proc in self.procedures:
            if not ignore_function(proc):
                asm = proc.assemble_proc(comments=comments, symbolized=symbolized)
                addr_and_assembly.extend(asm) 

        # sort it by the address - must be a stable sort!
        addr_and_assembly = sorted(addr_and_assembly, key=lambda x: x[0])
        all_assembly_lines.extend(line for _, line in addr_and_assembly)

        last_section = None

        if self._cgc_attachments_removed:
                                    all_data = self.data + self.extra_rodata + self.extra_data
        else:
            # to reduce memory usage, we put extra data in front of the original data in binary
            all_data = self.extra_data + self.data + self.extra_rodata

        #print("All labels2: {}".format([[y.name for _, y in x.labels] for x in all_data if len(x.labels)]))
        #print("All addrs2: {}".format([[hex(addr) for addr, _ in x.labels] for x in all_data if len(x.labels)]))
        #print("All addrs3: {}".format([hex(x.addr) for x in all_data]))

        seen = []
        for data in all_data:
            if data.addr in seen:
                l.error("Duplicate data: data[{}]".format(data.addr))
            seen.append(data.addr)

        seen_addrs = [] # TODO remove this?
        for data in all_data:
            if data.addr in seen_addrs:
                continue 
            #assert(not data.addr in seen_addrs)

            seen_addrs.append(data.addr)
            #print(data)
            if (data.section_name is None):
                data.section_name = ".rodata"
            if last_section is None or data.section_name != last_section:
                last_section = data.section_name
                all_assembly_lines.append("\t.section {section}\n\t.align {alignment}".format(
                    section=(last_section if last_section != '.init_array' else '.data'),
                    alignment=self.section_alignment(last_section)
                ))

            if data.sort == 'unknown' and data.size == 4: # TODO track this bug down better, seen with g_4 in csmith tests
                l.warning("Risky bugfix- Marking unknown of size 4 as an int")
                data.sort = 'integer'

            all_assembly_lines.append(data.data_assembly(comments=comments, symbolized=symbolized))

        seen_addrs2 = [] # TODO - find what's adding duplicate labels and delete
        for label in self.symbol_manager.addr_to_label:
            if (data.addr in seen_addrs2+seen_addrs):
                continue 
            print("Generate assembly for extra data in addr_to_label at 0x{:x}".format(data.addr))
            assert(not data.addr in seen_addrs2)
            seen_addrs2.append(data.addr)


            all_assembly_lines.append(data.data_assembly(comments=comments, symbolized=symbolized))
            #if len(data.labels):
                #print("Assemble2 code with label: {}".format(", ".join([x.name for _, x in data.labels])))

        s = "\n".join(all_assembly_lines)

        return s

    def add_data(self, addr, value): # TODO - remove or use, make decision
        # TODO: make angr happy
    
        assert("This isn't used" == 0)
        memory_data = self.cfg.memory_data.get(addr, None)
        print("Add data\t{}".format(name))
        if memory_data:
            data = Data(self, memory_data, section_name=".rodata", addr=addr, sort="pointer-array", size=4, initial_content=memory_data)
            self.data.append(data)
        else:
            l.error("Couldn't get memory_data for 0x%x", addr)

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

        if cgcpl_memory_data is None or cgcea_memory_data is None:
            return False

        if len(cgcpl_memory_data.refs) != 1:
            return False
        if len(cgcea_memory_data.refs) != 1:
            return False

        # check if the irsb addresses are the same
        if next(iter(cgcpl_memory_data.refs))[0] != next(iter(cgcea_memory_data.refs))[0]:
            return False

        insn_addr = next(iter(cgcpl_memory_data.refs))[2]
        # get the basic block
        cfg_node = self.cfg.get_any_node(insn_addr, anyaddr=True)
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

        glibc_functions_blacklist = {
            '_start',
            '_init',
            '_fini',
            '__gmon_start__',
            '__do_global_dtors_aux',
            'call_weak_fn',
            'frame_dummy',
            'atexit',
            'deregister_tm_clones',
            'register_tm_clones',
            '__x86.get_pc_thunk.bx',
            '__libc_csu_init',
            '__libc_csu_fini',
            '__do_global_ctors_aux',
            'call_frame_dummy',
            'call___do_global_dtors_aux',
            'call___do_global_ctors_aux'
        }

        glibc_data_blacklist = {
            '__TMC_END__',
            '_GLOBAL_OFFSET_TABLE_',
            '__JCR_END__',
            '__dso_handle',
            '__init_array_start',
            '__init_array_end',
            '__libc_csu_fini',
            '__stack_chk_guard',

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
            'program_invocation_short_',
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

        # TODO: temporary solution - we should get rid of the func that calls register_tm_clones but it's unnamed
        # we can leave it there if we leave register_tm_clones as well
        # This can probably be solved with the ignore_function blacklist now (TODO)
        if self.project.arch.name in ['PPC32']:
            glibc_functions_blacklist.remove('register_tm_clones')

        self.procedures = [p for p in self.procedures if p.name not in glibc_functions_blacklist and not p.is_plt]

        self.data = [d for d in self.data if not any(lbl.name in glibc_data_blacklist or lbl.name in glibc_functions_blacklist for _, lbl in d.labels)]

        for d in self.data:
            if d.sort == 'pointer-array':
                for i in xrange(len(d.content)):
                    ptr = d.content[i]
                    if isinstance(ptr, Label) and ptr.name in glibc_references_blacklist:
                        d.content[i] = 0

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
                if self.project.arch.name in ['PPC32']: # PPC32 can't have align 32, so align to 16
                    alignment = 0x10
                else:
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

        arch_options = None

        if self.project.arch in ['ARMEL']:
            arch_options = CFGArchOptions(self.project.arch, ret_jumpkind_heuristics=True)

        #"""
        cfg = self.project.analyses.CFG(normalize=True, resolve_indirect_jumps=True, collect_data_references=True,
                                        data_type_guessing_handlers=[
                                            self._sequence_handler,
                                            #self._cgc_extended_application_handler,
                                            self._unknown_data_size_handler,
                                        ],
                                        arch_options=arch_options
                                        )
        #"""
        #cfg = self.project.analyses.CFGAccurate()

        self.cfg = cfg
        #print("Project arch is {}".format(self.project.arch))

        # project.arch doens't have the capstone_x86_syntax for PPC
        has_x86_syntax = self.project.arch.name in ['X86', 'AMD64']

        if has_x86_syntax:
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

            if section in ('.got', '.plt', 'init', 'fini', '.plt.got'):
                continue

            procedure = Procedure(self, f, section=section)

            if f.addr in [x.addr for x in self.data]:
                l.warning("Added procedure at 0x%x but there's also data defined, deleting", f.addr)
                self.data[:] = [x for x in self.data if x.addr != f.addr]

            if f.addr in [x.addr for x in self.procedures]:
                l.warning("Want to add procedure at 0x%x but there's already a procedure there- SKIP", f.addr)
                continue
            self.procedures.append(procedure)


        self.procedures = sorted(self.procedures, key=lambda x: x.addr)

        # Data

        has_sections = len(self.project.loader.main_object.sections) > 0

        #print("All labels0: {}".format([x for x in self.data]))

        l.debug('Creating data entries...')
        for addr, memory_data in cfg._memory_data.iteritems():
            if memory_data.sort in ('code reference', ):
                continue

            if addr in [x.addr for x in self.procedures]: # TODO - Keep duplicates out in the first place
                #l.warning("Added data at 0x%x but there's also a proc defined there! Delete from procs", addr)
                self.procedures[:] = [x for x in self.procedures if x.addr != addr]

            # TODO: CGC specific
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

                bad_section_names = [".note.gnu.build-id"] # ignore certain section names

                if self.project.arch.name == "ARMEL":
                    bad_section_names.append([".ARM.exidx", ".ARM.extab"])

                if self.project.extract_libc_main:
                    bad_section_names.append([".init"])

                if section is not None and section.name not in bad_section_names:
                    data = Data(self, memory_data, section=section) # Here for everything
                    if data.addr not in [x.addr for x in self.data]:
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
        section_names_to_ignore = {'.init', '.fini', '.fini_array', '.jcr', '.dynamic', '.got.plt',
                                   '.eh_frame_hdr', '.eh_frame', '.rel.dyn', '.rel.plt', '.rela.dyn', '.rela.plt',
                                   '.dynstr', '.dynsym', '.interp', '.note.ABI-tag', '.note.gnu.build-id', '.gnu.hash',
                                   '.gnu.version', '.gnu.version_r', '.ctors', '.dtors',
                                   }

        if self.project.arch.name == "ARMEL":
            section_names_to_ignore.add(".ARM.exidx")
            section_names_to_ignore.add(".ARM.extab")

        # make sure there are always memory data entries pointing at the end of sections
        all_data_addrs = set(d.addr for d in self.data)
        all_procedure_addrs = set(f.addr for f in self.procedures)
        all_addrs = all_data_addrs | all_procedure_addrs

        if has_sections:
            for section in self.project.loader.main_object.sections:

                if section.name in section_names_to_ignore:
                    # skip all sections that are CGC or GCC specific
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
                        pointer_size = self.project.arch.bits / 8
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

        # TODO: CGC specific
        # CGC-specific data filtering
        self.data = [ d for d in self.data if d.section_name not in section_names_to_ignore ]

        # restore capstone X86 syntax at the end
        if has_x86_syntax and self.project.arch.capstone_x86_syntax != old_capstone_syntax:
            self.project.arch.capstone_x86_syntax = old_capstone_syntax
            self.project.factory.default_engine.clear_cache()

        l.debug('Initialized.')

    def _is_sequence(self, cfg, addr, size):
        data = self.fast_memory_load(addr, size, str)
        ints = [ord(i) for i in data]
        if len(set([(i - j) for i, j in zip(ints, ints[1:])])) == 1:
            # arithmetic progression
            # backoff: it should not be ending with a pointer
            closest_aligned_addr = (addr + size - 1) & 0xfffffffc
            ptr = self.fast_memory_load(closest_aligned_addr, 4, int, endness=self.project.arch.memory_endness)
            if self._is_pointer(cfg, ptr):
                return False

            return True
        return False

    @staticmethod
    def _is_pointer(cfg, ptr):
        if cfg._addr_belongs_to_section(ptr) is not None or cfg._addr_belongs_to_segment(ptr) is not None or \
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

        for i in xrange(5, min(256, max_size)):
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

        data = self.fast_memory_load(data_addr, 20, str)

        if data[:4] != 'The ':
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

        for offset in xrange(1, max_size):
            if self._is_sequence(cfg, data_addr + offset, 5):
                # a potential sequence is found
                sequence_offset = offset
                break

        if sequence_offset is not None:
            if self.project.arch.bits == 32:
                max_size = min(max_size, sequence_offset)
            elif self.project.arch.bits == 64:
                max_size = min(max_size, sequence_offset + 5)  # high 5 bytes might be all zeros...

        ptr_size = cfg.project.arch.bits / 8

        size = None

        for offset in xrange(1, max_size - ptr_size + 1):
            ptr = self.fast_memory_load(data_addr + offset, ptr_size, int, endness=cfg.project.arch.memory_endness)
            if self._is_pointer(cfg, ptr):
                size = offset
                break

        if size is not None:
            return 'unknown', size
        elif sequence_offset is not None:
            return 'unknown', sequence_offset
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
        candidates = [ i for i in self.cfg.memory_data.itervalues() if
                       i.sort in ('unknown', 'integer') and
                       i.size == self.project.arch.bits / 8 and
                       i.irsb_addr is not None
                       ]

        if not candidates:
            return False

        for candidate in candidates:

            # if the candidate is in .bss, we don't care about it
            sec = self.cfg._addr_belongs_to_section(candidate.address)
            if sec.name in ('.bss', '.got.plt'):
                continue

            # execute the single basic block and see how the value is used
            base_graph = networkx.DiGraph()
            candidate_node = self.cfg.get_any_node(candidate.irsb_addr)  # type: angr.analyses.cfg_node.CFGNode
            if candidate_node is None:
                continue
            base_graph.add_node(candidate_node)
            tmp_kb = KnowledgeBase(self.project, self.project.loader.main_object)
            cfg = self.project.analyses.CFGAccurate(kb=tmp_kb,
                                                    starts=(candidate.irsb_addr,),
                                                    keep_state=True,
                                                    base_graph=base_graph
                                                    )
            candidate_irsb = cfg.get_any_irsb(candidate.irsb_addr)  # type: SimIRSB
            ddg = self.project.analyses.DDG(kb=tmp_kb, cfg=cfg)

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
        #l.debug("Load {} bytes of memory at 0x{:x}: ".format(size, addr)),
        try:
            buff, _ = self.project.loader.memory.read_bytes_c(addr)
        except KeyError:
            return None

        data = self._ffi.unpack(self._ffi.cast('char*', buff), size)

        if data_type in (int, long):
            if endness == 'Iend_LE':

                if endness == 'Iend_LE':
                    fmt = "<"
                else:
                    fmt = ">"
                if size == 8:
                    fmt += "Q"
                elif size == 4:
                    fmt += "I"
                else:
                    raise BinaryError("Pointer size of %d is not supported" % size)

                return struct.unpack(fmt, data)[0]
            else:
                raise NotImplementedError("Only endness = Iend_LE is supported for now")

        else:
            return data

from angr.analyses import AnalysesHub
AnalysesHub.register_default('Reassembler', Reassembler)
