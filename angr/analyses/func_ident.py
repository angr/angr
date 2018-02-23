import re
from . import Analysis, register_analysis
from cle.backends import ELF, PE, Blob
from cle import ExternObject, KernelObject, TLSObject
from cle.address_translator import AT

import logging
log = logging.getLogger("func_ident")
log.setLevel(logging.DEBUG)


class FunctionIdentification(Analysis):

    def __init__(self, use_symbols=True, use_prologues=True,
                 force_segment=False, use_disassembly=True, code_regions=[]):
        """
        Identify functions statically in the binary.


        :param use_symbols: Use metadata from the binary, if available
        :param use_prologues: Use function prologue scanning.
        Will only scan in code regions, if any are specified
        :param use_disassembly: Use a disassembly-based prolog detection, instead
        of byte-level detection (slower)
        :param code_regions: Specify code regions.  If none are provided, the whole
        binary is scanned.
        """
        self.use_disassembly = use_disassembly
        self._force_segment = force_segment

        # Get all executable memory regions
        self._exec_memory_regions = self._executable_memory_regions(None, self._force_segment)
        self._exec_memory_region_size = sum([(end - start) for start, end in self._exec_memory_regions])
        self.function_addrs = set()
        self._binary = self.project.loader.main_object
        Analysis.__init__(self)

        if self.use_disassembly:
            self.capstone = self.project.arch.capstone

        if use_symbols:
            self.function_addrs = self.function_addrs.union(set(self._func_addrs_from_symbols()))
        if use_prologues:
            self.function_addrs = self.function_addrs.union(set(self._func_addrs_from_prologues()))
        log.info("Static function identification found %d functions" % len(list(self.function_addrs)))

    def _func_addrs_from_symbols(self):
        """
        Get all possible function addresses that are specified by the symbols in the binary

        :return: A set of addresses that are probably functions
        :rtype: set
        """

        symbols_by_addr = self._binary.symbols_by_addr

        func_addrs = set()

        for addr, sym in symbols_by_addr.iteritems():
            if sym.is_function:
                func_addrs.add(addr)
        log.debug("Found %d functions via symbols" % len(func_addrs))
        return func_addrs

    def _func_addrs_from_prologues(self):
        """
        Scan the entire program image for function prologues, and start code scanning at those positions

        :return: A list of possible function addresses
        """

        # Pre-compile all regexes
        regexes = list()
        for ins_regex in self.project.arch.function_prologs:
            r = re.compile(ins_regex)
            regexes.append(r)

        # Construct the binary blob first
        strides = self.project.loader.main_object.memory.stride_repr

        unassured_functions = []

        for start_, _, bytes_ in strides:
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        if self._addr_in_exec_memory_regions(position):
                            unassured_functions.append(AT.from_rva(position, self._binary).to_mva())
        log.debug("Found %d functions via prologue scanning" % len(unassured_functions))
        return unassured_functions

    # TODO:
    # TODO: Move the following to another common package some day
    # TODO:

    def _is_region_extremely_sparse(self, start, end, base_state=None):
        """
        Check whether the given memory region is extremely sparse, i.e., all bytes are the same value.

        :param int start: The beginning of the region.
        :param int end:   The end of the region.
        :param base_state: The base state (optional).
        :return:           True if the region is extremely sparse, False otherwise.
        :rtype:            bool
        """

        all_bytes = None

        if base_state is not None:
            all_bytes = base_state.memory.load(start, end - start + 1)
            try:
                n = base_state.se.eval(all_bytes)
                all_bytes = hex(n)[2:].strip('L').decode("hex")
            except SimError:
                all_bytes = None

        size = end - start + 1

        if all_bytes is None:
            # load from the binary
            all_bytes = self._fast_memory_load_bytes(start, size)

        if all_bytes is None:
            return True

        if len(all_bytes) < size:
            l.warning("_is_region_extremely_sparse: The given region %#x-%#x is not a continuous memory region in the "
                      "memory space. Only the first %d bytes (%#x-%#x) are processed.", start, end, len(all_bytes),
                      start, start + len(all_bytes) - 1)

        the_byte_value = None
        for b in all_bytes:
            if the_byte_value is None:
                the_byte_value = b
            else:
                if the_byte_value != b:
                    return False

        return True

    def _should_skip_region(self, region_start):
        """
        Some regions usually do not contain any executable code, but are still marked as executable. We should skip
        those regions by default.

        :param int region_start: Address of the beginning of the region.
        :return:                 True/False
        :rtype:                  bool
        """

        obj = self.project.loader.find_object_containing(region_start)
        if obj is None:
            return False
        if isinstance(obj, PE):
            section = obj.find_section_containing(region_start)
            if section is None:
                return False
            if section.name in {'.textbss'}:
                return True

        return False

    def _executable_memory_regions(self, binary=None, force_segment=False):
        """
        Get all executable memory regions from the binaries

        :param binary: Binary object to collect regions from. If None, regions from all project binary objects are used.
        :param bool force_segment: Rely on binary segments instead of sections.
        :return: A sorted list of tuples (beginning_address, end_address)
        """

        if binary is None:
            binaries = self.project.loader.all_objects
        else:
            binaries = [binary]

        memory_regions = []

        for b in binaries:
            if isinstance(b, ELF):
                # If we have sections, we get result from sections
                if not force_segment and b.sections:
                    # Get all executable sections
                    for section in b.sections:
                        if section.is_executable:
                            tpl = (section.min_addr, section.max_addr)
                            memory_regions.append(tpl)

                else:
                    # Get all executable segments
                    for segment in b.segments:
                        if segment.is_executable:
                            tpl = (segment.min_addr, segment.max_addr)
                            memory_regions.append(tpl)

            elif isinstance(b, PE):
                for section in b.sections:
                    if section.is_executable:
                        tpl = (section.min_addr, section.max_addr)
                        memory_regions.append(tpl)

            elif isinstance(b, Blob):
                # a blob is entirely executable
                tpl = (b.min_addr, b.max_addr)
                memory_regions.append(tpl)

            elif isinstance(b, (ExternObject, KernelObject, TLSObject)):
                pass

            else:
                l.warning('Unsupported object format "%s". Treat it as an executable.', b.__class__.__name__)

                tpl = (b.min_addr, b.max_addr)
                memory_regions.append(tpl)

        if not memory_regions:
            memory_regions = [(start, start + len(cbacker)) for start, cbacker in self.project.loader.memory.cbackers]

        memory_regions = sorted(memory_regions, key=lambda x: x[0])

        return memory_regions

    def _addr_in_exec_memory_regions(self, addr):
        """
        Test if the address belongs to an executable memory region.

        :param int addr: The address to test
        :return: True if the address belongs to an exectubale memory region, False otherwise
        :rtype: bool
        """

        for start, end in self._exec_memory_regions:
            if start <= addr < end:
                return True
        return False

    def _addr_belongs_to_section(self, addr):
        """
        Return the section object that the address belongs to.

        :param int addr: The address to test
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Section
        """

        obj = self.project.loader.find_object_containing(addr)

        if obj is None:
            return None

        if isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        return obj.find_section_containing(addr)

    def _addrs_belong_to_same_section(self, addr_a, addr_b):
        """
        Test if two addresses belong to the same section.

        :param int addr_a:  The first address to test.
        :param int addr_b:  The second address to test.
        :return:            True if the two addresses belong to the same section or both of them do not belong to any
                            section, False otherwise.
        :rtype:             bool
        """

        obj = self.project.loader.find_object_containing(addr_a)

        if obj is None:
            # test if addr_b also does not belong to any object
            obj_b = self.project.loader.find_object_containing(addr_b)
            if obj_b is None:
                return True
            return False

        src_section = obj.find_section_containing(addr_a)
        if src_section is None:
            # test if addr_b also does not belong to any section
            dst_section = obj.find_section_containing(addr_b)
            if dst_section is None:
                return True
            return False

        return src_section.contains_addr(addr_b)

    def _addr_next_section(self, addr):
        """
        Return the next section object after the given address.

        :param int addr: The address to test
        :return: The next section that goes after the given address, or None if there is no section after the address,
                 or if section information is not available.
        :rtype: cle.Section
        """

        obj = self.project.loader.find_object_containing(addr)

        if obj is None:
            return None

        if isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a special CLE section
            return None

        for section in obj.sections:
            start = section.vaddr

            if addr < start:
                return section

        return None

    def _addr_belongs_to_segment(self, addr):
        """
        Return the section object that the address belongs to.

        :param int addr: The address to test
        :return: The section that the address belongs to, or None if the address does not belong to any section, or if
                section information is not available.
        :rtype: cle.Segment
        """

        obj = self.project.loader.find_object_containing(addr)

        if obj is None:
            return None

        if isinstance(obj, (ExternObject, KernelObject, TLSObject)):
            # the address is from a section allocated by angr.
            return None

        return obj.find_segment_containing(addr)


    def _fast_memory_load(self, addr):
        """
        Perform a fast memory loading of static content from static regions, a.k.a regions that are mapped to the
        memory by the loader.

        :param int addr: Address to read from.
        :return: A tuple of the data (cffi.CData) and the max size in the current continuous block, or (None, None) if
                 the address does not exist.
        :rtype: tuple
        """

        try:
            buff, size = self.project.loader.memory.read_bytes_c(addr)
            return buff, size

        except KeyError:
            return None, None

    def _fast_memory_load_byte(self, addr):
        """
        Perform a fast memory loading of a byte.

        :param int addr: Address to read from.
        :return:         A char or None if the address does not exist.
        :rtype:          str or None
        """

        return self._fast_memory_load_bytes(addr, 1)

    def _fast_memory_load_bytes(self, addr, length):
        """
        Perform a fast memory loading of a byte.

        :param int addr: Address to read from.
        :param int length: Size of the string to load.
        :return:         A string or None if the address does not exist.
        :rtype:          str or None
        """

        buf, size = self._fast_memory_load(addr)
        if buf is None:
            return None
        if size == 0:
            return None

        # Make sure it does not go over-bound
        length = min(length, size)

        char_str = self._ffi.unpack(self._ffi.cast('char*', buf), length) # type: str
        return char_str

    def _fast_memory_load_pointer(self, addr):
        """
        Perform a fast memory loading of a pointer.

        :param int addr: Address to read from.
        :return:         A pointer or None if the address does not exist.
        :rtype:          int
        """

        pointer_size = self.project.arch.bits / 8
        buf, size = self._fast_memory_load(addr)
        if buf is None:
            return None

        if self.project.arch.memory_endness == 'Iend_LE':
            fmt = "<"
        else:
            fmt = ">"

        if pointer_size == 8:
            if size >= 8:
                fmt += "Q"
            else:
                # Insufficient bytes left in the current block for making an 8-byte pointer
                return None
        elif pointer_size == 4:
            if size >= 4:
                fmt += "I"
            else:
                # Insufficient bytes left in the current block for making a 4-byte pointer.
                return None
        else:
            raise AngrCFGError("Pointer size of %d is not supported" % pointer_size)

        ptr_str = self._ffi.unpack(self._ffi.cast('char*', buf), pointer_size)
        ptr = struct.unpack(fmt, ptr_str)[0]  # type:int

        return ptr


register_analysis(FunctionIdentification, 'FunctionIdentification')

