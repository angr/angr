import itertools
import logging
import math
import re
import string
import struct
from collections import defaultdict

from bintrees import AVLTree

import claripy
import cle
import pyvex
from cle.address_translator import AT

from .cfg_arch_options import CFGArchOptions
from .cfg_base import CFGBase, IndirectJump
from .cfg_node import CFGNode
from .indirect_jump_resolvers.default_resolvers import default_indirect_jump_resolvers
from .. import register_analysis
from ..forward_analysis import ForwardAnalysis
from ... import sim_options as o
from ...engines import SimEngineVEX
from ...errors import AngrCFGError, SimEngineError, SimMemoryError, SimTranslationError, SimValueError

VEX_IRSB_MAX_SIZE = 400

l = logging.getLogger("angr.analyses.cfg.cfg_fast")


class Segment(object):
    """
    Representing a memory block. This is not the "Segment" in ELF memory model
    """

    __slots__ = ['start', 'end', 'sort']

    def __init__(self, start, end, sort):
        """
        :param int start:   Start address.
        :param int end:     End address.
        :param str sort:    Type of the segment, can be code, data, etc.
        :return: None
        """

        self.start = start
        self.end = end
        self.sort = sort

    def __repr__(self):
        s = "[%#x-%#x, %s]" % (self.start, self.end, self.sort)
        return s

    @property
    def size(self):
        """
        Calculate the size of the Segment.

        :return: Size of the Segment.
        :rtype: int
        """
        return self.end - self.start

    def copy(self):
        """
        Make a copy of the Segment.

        :return: A copy of the Segment instance.
        :rtype: angr.analyses.cfg_fast.Segment
        """
        return Segment(self.start, self.end, self.sort)


class SegmentList(object):
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

    __slots__ = ['_list', '_bytes_occupied']

    def __init__(self):
        self._list = []
        self._bytes_occupied = 0

    #
    # Overridden methods
    #

    def __len__(self):
        return len(self._list)

    #
    # Private methods
    #

    def _search(self, addr):
        """
        Checks which segment tha the address `addr` should belong to, and, returns the offset of that segment.
        Note that the address may not actually belong to the block.

        :param addr: The address to search
        :return: The offset of the segment.
        """

        start = 0
        end = len(self._list)

        while start != end:
            mid = (start + end) / 2

            segment = self._list[mid]
            if addr < segment.start:
                end = mid
            elif addr >= segment.end:
                start = mid + 1
            else:
                # Overlapped :(
                start = mid
                break

        return start

    def _insert_and_merge(self, address, size, sort, idx):
        """
        Determines whether the block specified by (address, size) should be merged with adjacent blocks.

        :param int address: Starting address of the block to be merged.
        :param int size: Size of the block to be merged.
        :param str sort: Type of the block.
        :param int idx: ID of the address.
        :return: None
        """

        # sanity check
        if idx > 0 and address + size <= self._list[idx - 1].start:
            # There is a bug, since _list[idx] must be the closest one that is less than the current segment
            l.warning("BUG FOUND: new segment should always be greater than _list[idx].")
            # Anyways, let's fix it.
            self._insert_and_merge(address, size, sort, idx - 1)
            return

        # Insert the block first
        # The new block might be overlapping with other blocks. _insert_and_merge_core will fix the overlapping.
        if idx == len(self._list):
            self._list.append(Segment(address, address + size, sort))
        else:
            self._list.insert(idx, Segment(address, address + size, sort))
        # Apparently _bytes_occupied will be wrong if the new block overlaps with any existing block. We will fix it
        # later
        self._bytes_occupied += size

        # Search forward to merge blocks if necessary
        pos = idx
        while pos < len(self._list):
            merged, pos, bytes_change = self._insert_and_merge_core(pos, "forward")

            if not merged:
                break

            self._bytes_occupied += bytes_change

        # Search backward to merge blocks if necessary
        if pos >= len(self._list):
            pos = len(self._list) - 1

        while pos > 0:
            merged, pos, bytes_change = self._insert_and_merge_core(pos, "backward")

            if not merged:
                break

            self._bytes_occupied += bytes_change

    def _insert_and_merge_core(self, pos, direction):
        """
        The core part of method _insert_and_merge.

        :param int pos:         The starting position.
        :param str direction:   If we are traversing forwards or backwards in the list. It determines where the "sort"
                                of the overlapping memory block comes from. If everything works as expected, "sort" of
                                the overlapping block is always equal to the segment occupied most recently.
        :return: A tuple of (merged (bool), new position to begin searching (int), change in total bytes (int)
        :rtype: tuple
        """

        bytes_changed = 0

        if direction == "forward":
            if pos == len(self._list) - 1:
                return False, pos, 0
            previous_segment = self._list[pos]
            previous_segment_pos = pos
            segment = self._list[pos + 1]
            segment_pos = pos + 1
        else:  # if direction == "backward":
            if pos == 0:
                return False, pos, 0
            segment = self._list[pos]
            segment_pos = pos
            previous_segment = self._list[pos - 1]
            previous_segment_pos = pos - 1

        merged = False
        new_pos = pos

        if segment.start <= previous_segment.end:
            # we should always have new_start+new_size >= segment.start

            if segment.sort == previous_segment.sort:
                # They are of the same sort - we should merge them!
                new_end = max(previous_segment.end, segment.start + segment.size)
                new_start = min(previous_segment.start, segment.start)
                new_size = new_end - new_start
                self._list[segment_pos] = Segment(new_start, new_end, segment.sort)
                self._list.pop(previous_segment_pos)
                bytes_changed = -(segment.size + previous_segment.size - new_size)

                merged = True
                new_pos = previous_segment_pos

            else:
                # Different sorts. It's a bit trickier.
                if segment.start == previous_segment.end:
                    # They are adjacent. Just don't merge.
                    pass
                else:
                    # They are overlapping. We will create one, two, or three different blocks based on how they are
                    # overlapping
                    new_segments = [ ]
                    if segment.start < previous_segment.start:
                        new_segments.append(Segment(segment.start, previous_segment.start, segment.sort))

                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        new_segments.append(Segment(previous_segment.start, previous_segment.end, sort))

                        if segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        elif segment.end > previous_segment.end:
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                    else:  # segment.start >= previous_segment.start
                        if segment.start > previous_segment.start:
                            new_segments.append(Segment(previous_segment.start, segment.start, previous_segment.sort))
                        sort = previous_segment.sort if direction == "forward" else segment.sort
                        if segment.end > previous_segment.end:
                            new_segments.append(Segment(segment.start, previous_segment.end, sort))
                            new_segments.append(Segment(previous_segment.end, segment.end, segment.sort))
                        elif segment.end < previous_segment.end:
                            new_segments.append(Segment(segment.start, segment.end, sort))
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
                        else:
                            new_segments.append(Segment(segment.start, segment.end, sort))

                    # merge segments in new_segments array if they are of the same sort
                    i = 0
                    while len(new_segments) > 1 and i < len(new_segments) - 1:
                        s0 = new_segments[i]
                        s1 = new_segments[i + 1]
                        if s0.sort == s1.sort:
                            new_segments = new_segments[ : i] + [ Segment(s0.start, s1.end, s0.sort) ] + new_segments[i + 2 : ]
                        else:
                            i += 1

                    # Put new segments into self._list
                    old_size = sum([ seg.size for seg in self._list[previous_segment_pos : segment_pos + 1] ])
                    new_size = sum([ seg.size for seg in new_segments ])
                    bytes_changed = new_size - old_size

                    self._list = self._list[ : previous_segment_pos] + new_segments + self._list[ segment_pos + 1 : ]

                    merged = True

                    if direction == "forward":
                        new_pos = previous_segment_pos + len(new_segments)
                    else:
                        new_pos = previous_segment_pos

        return merged, new_pos, bytes_changed

    def _dbg_output(self):
        """
        Returns a string representation of the segments that form this SegmentList

        :return: String representation of contents
        :rtype: str
        """
        s = "["
        lst = []
        for segment in self._list:
            lst.append(repr(segment))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
        """
        Iterates over list checking segments with same sort do not overlap

        :raise: Exception: if segments overlap space with same sort
        """
        # old_start = 0
        old_end = 0
        old_sort = ""
        for segment in self._list:
            if segment.start <= old_end and segment.sort == old_sort:
                raise Exception("Error in SegmentList: blocks are not merged")
            # old_start = start
            old_end = segment.end
            old_sort = segment.sort

    #
    # Public methods
    #

    def next_free_pos(self, address):
        """
        Returns the next free position with respect to an address, including that address itself

        :param address: The address to begin the search with (including itself)
        :return: The next free position
        """

        idx = self._search(address)
        if idx < len(self._list) and self._list[idx].start <= address < self._list[idx].end:
            # Occupied
            i = idx
            while i + 1 < len(self._list) and self._list[i].end == self._list[i + 1].start:
                i += 1
            if i == len(self._list):
                return self._list[-1].end

            return self._list[i].end

        return address

    def is_occupied(self, address):
        """
        Check if an address belongs to any segment

        :param address: The address to check
        :return: True if this address belongs to a segment, False otherwise
        """

        idx = self._search(address)
        if len(self._list) <= idx:
            return False
        if self._list[idx].start <= address < self._list[idx].end:
            return True
        if idx > 0 and address < self._list[idx - 1].end:
            # TODO: It seems that this branch is never reached. Should it be removed?
            return True
        return False

    def occupied_by_sort(self, address):
        """
        Check if an address belongs to any segment, and if yes, returns the sort of the segment

        :param int address: The address to check
        :return: Sort of the segment that occupies this address
        :rtype: str
        """

        idx = self._search(address)
        if len(self._list) <= idx:
            return None
        if self._list[idx].start <= address < self._list[idx].end:
            return self._list[idx].sort
        if idx > 0 and address < self._list[idx - 1].end:
            # TODO: It seems that this branch is never reached. Should it be removed?
            return self._list[idx - 1].sort
        return None

    def occupy(self, address, size, sort):
        """
        Include a block, specified by (address, size), in this segment list.

        :param int address:     The starting address of the block.
        :param int size:        Size of the block.
        :param str sort:        Type of the block.
        :return: None
        """

        if size <= 0:
            # Cannot occupy a non-existent block
            return

        # l.debug("Occpuying 0x%08x-0x%08x", address, address + size)
        if not self._list:
            self._list.append(Segment(address, address + size, sort))
            self._bytes_occupied += size
            return
        # Find adjacent element in our list
        idx = self._search(address)
        # print idx

        self._insert_and_merge(address, size, sort, idx)

        # self._debug_check()

    def copy(self):
        """
        Make a copy of the SegmentList.

        :return: A copy of the SegmentList instance.
        :rtype: angr.analyses.cfg_fast.SegmentList
        """
        n = SegmentList()

        n._list = [ a.copy() for a in self._list ]
        n._bytes_occupied = self._bytes_occupied

    #
    # Properties
    #

    @property
    def occupied_size(self):
        """
        The sum of sizes of all blocks

        :return: An integer
        """

        return self._bytes_occupied

    @property
    def has_blocks(self):
        """
        Returns if this segment list has any block or not. !is_empty

        :return: True if it's not empty, False otherwise
        """

        return len(self._list) > 0


class FunctionReturn(object):
    """
    FunctionReturn describes a function call in a specific location and its return location. Hashable and equatable
    """

    def __init__(self, callee_func_addr, caller_func_addr, call_site_addr, return_to):
        self.callee_func_addr = callee_func_addr
        self.caller_func_addr = caller_func_addr
        self.call_site_addr = call_site_addr
        self.return_to = return_to

    def __eq__(self, other):
        """
        Comparison

        :param FunctionReturn other: The other object
        :return: True if equal, False otherwise
        """
        return self.callee_func_addr == other.callee_func_addr and \
                self.caller_func_addr == other.caller_func_addr and \
                self.call_site_addr == other.call_site_addr and \
                self.return_to == other.return_to

    def __hash__(self):
        return hash((self.callee_func_addr, self.caller_func_addr, self.call_site_addr, self.return_to))


class MemoryData(object):
    """
    MemoryData describes the syntactic contents of single address of memory along with a set of references to this
    address (when not from previous instruction).
    """
    def __init__(self, address, size, sort, irsb, irsb_addr, stmt, stmt_idx, pointer_addr=None, max_size=None,
                 insn_addr=None):
        self.address = address
        self.size = size
        self.sort = sort
        self.irsb = irsb
        self.irsb_addr = irsb_addr
        self.stmt = stmt
        self.stmt_idx = stmt_idx
        self.insn_addr = insn_addr

        self.max_size = max_size
        self.pointer_addr = pointer_addr

        self.content = None  # optional

        self.refs = set()
        if irsb_addr and stmt_idx:
            self.refs.add((irsb_addr, stmt_idx, insn_addr))

    def __repr__(self):
        return "\\%#x, %s, %s/" % (self.address,
                                   "%d bytes" % self.size if self.size is not None else "size unknown",
                                   self.sort
                                   )

    def copy(self):
        """
        Make a copy of the MemoryData.

        :return: A copy of the MemoryData instance.
        :rtype: angr.analyses.cfg_fast.MemoryData
        """
        s = MemoryData(self.address, self.size, self.sort, self.irsb, self.irsb_addr, self.stmt, self.stmt_idx,
                       pointer_addr=self.pointer_addr, max_size=self.max_size, insn_addr=self.insn_addr
                       )
        s.refs = self.refs.copy()

        return s

    def add_ref(self, irsb_addr, stmt_idx, insn_addr):
        """
        Add a reference from code to this memory data.

        :param int irsb_addr: Address of the basic block.
        :param int stmt_idx: ID of the statement referencing this data entry.
        :param int insn_addr: Address of the instruction referencing this data entry.
        :return: None
        """

        ref = (irsb_addr, stmt_idx, insn_addr)
        if ref not in self.refs:
            self.refs.add(ref)

class MemoryDataReference(object):
    def __init__(self, ref_ins_addr):
        self.ref_ins_addr = ref_ins_addr


class CFGJob(object):
    """
    Defines a job to work on during the CFG recovery
    """

    def __init__(self, addr, func_addr, jumpkind, ret_target=None, last_addr=None, src_node=None, src_ins_addr=None,
                 src_stmt_idx=None, returning_source=None, syscall=False):
        self.addr = addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.ret_target = ret_target
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_ins_addr = src_ins_addr
        self.src_stmt_idx = src_stmt_idx
        self.returning_source = returning_source
        self.syscall = syscall

    def __repr__(self):
        return "<CFGJob%s %#08x @ func %#08x>" % (" syscall" if self.syscall else "", self.addr, self.func_addr)

    def __eq__(self, other):
        return self.addr == other.addr and \
                self.func_addr == other.func_addr and \
                self.jumpkind == other.jumpkind and \
                self.ret_target == other.ret_target and \
                self.last_addr == other.last_addr and \
                self.src_node == other.src_node and \
                self.src_stmt_idx == other.src_stmt_idx and \
                self.src_ins_addr == other.src_ins_addr and \
                self.returning_source == other.returning_source and \
                self.syscall == other.syscall

    def __hash__(self):
        return hash((self.addr, self.func_addr, self.jumpkind, self.ret_target, self.last_addr, self.src_node,
                     self.src_stmt_idx, self.src_ins_addr, self.returning_source, self.syscall)
                    )


class CFGFast(ForwardAnalysis, CFGBase):    # pylint: disable=abstract-method
    """
    We find functions inside the given binary, and build a control-flow graph in very fast manners: instead of
    simulating program executions, keeping track of states, and performing expensive data-flow analysis, CFGFast will
    only perform light-weight analyses combined with some heuristics, and with some strong assumptions.

    In order to identify as many functions as possible, and as accurate as possible, the following operation sequence
    is followed:

    # Active scanning

        - If the binary has "function symbols" (TODO: this term is not accurate enough), they are starting points of
            the code scanning
        - If the binary does not have any "function symbol", we will first perform a function prologue scanning on the
            entire binary, and start from those places that look like function beginnings
        - Otherwise, the binary's entry point will be the starting point for scanning

    # Passive scanning

        - After all active scans are done, we will go through the whole image and scan all code pieces

    Due to the nature of those techniques that are used here, a base address is often not required to use this analysis
    routine. However, with a correct base address, CFG recovery will almost always yield a much better result. A custom
    analysis, called GirlScout, is specifically made to recover the base address of a binary blob. After the base
    address is determined, you may want to reload the binary with the new base address by creating a new Project object,
    and then re-recover the CFG.
    """

    # TODO: Move arch_options to CFGBase, and add those logic to CFGAccurate as well.
    # TODO: Identify tail call optimization, and correctly mark the target as a new function

    PRINTABLES = string.printable.replace("\x0b", "").replace("\x0c", "")

    def __init__(self,
                 binary=None,
                 regions=None,
                 pickle_intermediate_results=False,
                 symbols=True,
                 function_prologues=True,
                 resolve_indirect_jumps=True,
                 force_segment=False,
                 force_complete_scan=True,
                 indirect_jump_target_limit=100000,
                 collect_data_references=False,
                 extra_cross_references=False,
                 normalize=False,
                 start_at_entry=True,
                 function_starts=None,
                 extra_memory_regions=None,
                 data_type_guessing_handlers=None,
                 arch_options=None,
                 indirect_jump_resolvers=None,
                 base_state=None,
                 exclude_sparse_regions=True,
                 skip_specific_regions=True,
                 heuristic_plt_resolving=None,
                 start=None,  # deprecated
                 end=None,  # deprecated
                 **extra_arch_options
                 ):
        """
        :param binary:                  The binary to recover CFG on. By default the main binary is used.
        :param iterable regions:        A list of tuples in the form of (start address, end address) describing memory
                                        regions that the CFG should cover.
        :param bool pickle_intermediate_results: If we want to store the intermediate results or not.
        :param bool symbols:            Get function beginnings from symbols in the binary.
        :param bool function_prologues: Scan the binary for function prologues, and use those positions as function
                                        beginnings
        :param bool resolve_indirect_jumps: Try to resolve indirect jumps. This is necessary to resolve jump targets
                                            from jump tables, etc.
        :param bool force_segment:      Force CFGFast to rely on binary segments instead of sections.
        :param bool force_complete_scan:    Perform a complete scan on the binary and maximize the number of identified
                                            code blocks.
        :param bool collect_data_references: If CFGFast should collect data references from individual basic blocks or
                                             not.
        :param bool extra_cross_references:  True if we should collect data references for all places in the program
                                             that access each memory data entry, which requires more memory, and is
                                             noticeably slower. Setting it to False means each memory data entry has at
                                             most one reference (which is the initial one).
        :param bool normalize:          Normalize the CFG as well as all function graphs after CFG recovery.
        :param bool start_at_entry:     Begin CFG recovery at the entry point of this project. Setting it to False
                                        prevents CFGFast from viewing the entry point as one of the starting points of
                                        code scanning.
        :param list function_starts:    A list of extra function starting points. CFGFast will try to resume scanning
                                        from each address in the list.
        :param list extra_memory_regions: A list of 2-tuple (start-address, end-address) that shows extra memory
                                          regions. Integers falling inside will be considered as pointers.
        :param list indirect_jump_resolvers: A custom list of indirect jump resolvers. If this list is None or empty,
                                             default indirect jump resolvers specific to this architecture and binary
                                             types will be loaded.
        :param base_state:              A state to use as a backer for all memory loads
        :param int start:               (Deprecated) The beginning address of CFG recovery.
        :param int end:                 (Deprecated) The end address of CFG recovery.
        :param CFGArchOptions arch_options: Architecture-specific options.
        :param dict extra_arch_options: Any key-value pair in kwargs will be seen as an arch-specific option and will
                                        be used to set the option value in self._arch_options.

        Extra parameters that angr.Analysis takes:

        :param progress_callback:       Specify a callback function to get the progress during CFG recovery.
        :param bool show_progressbar:   Should CFGFast show a progressbar during CFG recovery or not.
        :return: None
        """

        ForwardAnalysis.__init__(self, allow_merging=False)
        CFGBase.__init__(
            self,
            'fast',
            0,
            normalize=normalize,
            binary=binary,
            force_segment=force_segment,
            base_state=base_state)

        # necessary warnings
        if self.project.loader._auto_load_libs is True and end is None and len(self.project.loader.all_objects) > 3 \
                and regions is None:
            l.warning('"auto_load_libs" is enabled. With libraries loaded in project, CFGFast will cover libraries, '
                      'which may take significantly more time than expected. You may reload the binary with '
                      '"auto_load_libs" disabled, or specify "regions" to limit the scope of CFG recovery.'
                      )

        if start is not None or end is not None:
            l.warning('"start" and "end" are deprecated and will be removed soon. Please use "regions" to specify one '
                      'or more memory regions instead.'
                      )
            if regions is None:
                regions = [ (start, end) ]
            else:
                l.warning('"regions", "start", and "end" are all specified. Ignoring "start" and "end".')

        regions = regions if regions is not None else self._executable_memory_regions(binary=None,
                                                                                      force_segment=force_segment
                                                                                      )
        if exclude_sparse_regions:
            new_regions = [ ]
            for start_, end_ in regions:
                if not self._is_region_extremely_sparse(start_, end_, base_state=base_state):
                    new_regions.append((start_, end_))
            regions = new_regions
        if skip_specific_regions:
            if base_state is not None:
                l.warning("You specified both base_state and skip_specific_regions. They may conflict with each other.")
            new_regions = [ ]
            for start_, end_ in regions:
                if not self._should_skip_region(start_):
                    new_regions.append((start_, end_))
            regions = new_regions
        if not regions:
            raise AngrCFGError("Regions are empty or all regions are skipped. You may want to manually specify regions.")
        # sort the regions
        regions = sorted(regions, key=lambda x: x[0])
        self._regions_size = sum((b - a) for a, b in regions)
        # initial self._regions as an AVL tree
        self._regions = AVLTree()
        for start_, end_ in regions:
            self._regions.insert(start_, end_)

        self._pickle_intermediate_results = pickle_intermediate_results
        self._indirect_jump_target_limit = indirect_jump_target_limit
        self._collect_data_ref = collect_data_references

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self._force_complete_scan = force_complete_scan

        if heuristic_plt_resolving is None:
            # If unspecified, we only enable heuristic PLT resolving when there is at least one binary loaded with the
            # ELF backend
            self._heuristic_plt_resolving = len(self.project.loader.all_elf_objects) > 0
        else:
            self._heuristic_plt_resolving = heuristic_plt_resolving

        self._start_at_entry = start_at_entry
        self._extra_function_starts = function_starts

        self._extra_memory_regions = extra_memory_regions

        self._extra_cross_references = extra_cross_references

        try:
            self._arch_options = arch_options if arch_options is not None else CFGArchOptions(self.project.arch,
                                                                                              **extra_arch_options
                                                                                              )
        except KeyError:
            raise

        self._data_type_guessing_handlers = [ ] if data_type_guessing_handlers is None else data_type_guessing_handlers

        l.debug("CFG recovery covers %d regions:", len(self._regions))
        for start_addr, end_addr in self._regions.iter_items():
            l.debug("... %#x - %#x", start_addr, end_addr)

        # A mapping between address and the actual data in memory
        self._memory_data = { }
        # A mapping between address of the instruction that's referencing the memory data and the memory data itself
        self.insn_addr_to_memory_data = { }

        self._initial_state = None
        self._next_addr = None

        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

        self._indirect_jumps_to_resolve = set()

        self._jump_tables = { }

        self._function_addresses_from_symbols = self._func_addrs_from_symbols()

        self._function_prologue_addrs = None
        self._remaining_function_prologue_addrs = None

        #
        # Indirect jump resolvers
        #
        # TODO: make it compatible with CFGAccurate

        self.timeless_indirect_jump_resolvers = [ ]
        self.indirect_jump_resolvers = [ ]
        if not indirect_jump_resolvers:
            indirect_jump_resolvers = default_indirect_jump_resolvers(self._binary, self.project)
        if indirect_jump_resolvers:
            # split them into different groups for the sake of speed
            for ijr in indirect_jump_resolvers:
                if ijr.timeless:
                    self.timeless_indirect_jump_resolvers.append(ijr)
                else:
                    if self._resolve_indirect_jumps:
                        self.indirect_jump_resolvers.append(ijr)

        l.info("Loaded %d indirect jump resolvers (%d timeless, %d generic).",
               len(self.timeless_indirect_jump_resolvers) + len(self.indirect_jump_resolvers),
               len(self.timeless_indirect_jump_resolvers),
               len(self.indirect_jump_resolvers)
               )

        #
        # Variables used during analysis
        #
        self._pending_jobs = None
        self._traced_addresses = None
        self._function_returns = None
        self._function_exits = None

        self._graph = None

        # Start working!
        self._analyze()

    #
    # Utils
    #

    @staticmethod
    def _calc_entropy(data, size=None):
        """
        Calculate the entropy of a piece of data

        :param data: The target data to calculate entropy on
        :param size: Size of the data, Optional.
        :return: A float
        """

        if not data:
            return 0
        entropy = 0
        if size is None:
            size = len(data)

        data = str(pyvex.ffi.buffer(data, size))
        for x in xrange(0, 256):
            p_x = float(data.count(chr(x))) / size
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    #
    # Properties
    #

    @property
    def memory_data(self):
        return self._memory_data

    @property
    def _insn_addr_to_memory_data(self):
        l.warning('_insn_addr_to_memory_data has been made public and is deprecated. Please fix your code accordingly.')
        return self.insn_addr_to_memory_data

    #
    # Private methods
    #

    def __setstate__(self, s):
        self._graph = s['graph']
        self.indirect_jumps = s['indirect_jumps']
        self._nodes_by_addr = s['_nodes_by_addr']
        self._memory_data = s['_memory_data']

    def __getstate__(self):
        s = {
            "graph": self.graph,
            "indirect_jumps": self.indirect_jumps,
            '_nodes_by_addr': self._nodes_by_addr,
            '_memory_data': self._memory_data,
        }
        return s

    # Methods for determining scanning scope

    def _inside_regions(self, address):
        """
        Check if the address is inside any existing region.

        :param int address: Address to check.
        :return:            True if the address is within one of the memory regions, False otherwise.
        :rtype:             bool
        """

        try:
            start_addr, end_addr = self._regions.floor_item(address)
            return start_addr <= address < end_addr
        except KeyError:
            return False

    def _get_min_addr(self):
        """
        Get the minimum address out of all regions. We assume self._regions is sorted.

        :return: The minimum address.
        :rtype:  int
        """

        if not self._regions:
            l.error("self._regions is empty or not properly set.")
            return None

        return self._regions.min_key()

    def _next_address_in_regions(self, address):
        """
        Return the next immediate address that is inside any of the regions.

        :param int address: The address to start scanning.
        :return:            The next address that is inside one of the memory regions.
        :rtype:             int
        """

        try:
            start_addr, end_addr = self._regions.floor_item(address)
            if start_addr <= address < end_addr:
                return address
            else:
                return self._regions.ceiling_key(address)
        except KeyError:
            return None

    # Methods for scanning the entire image

    def _next_unscanned_addr(self, alignment=None):
        """
        Find the next address that we haven't processed

        :param alignment: Assures the address returns must be aligned by this number
        :return: An address to process next, or None if all addresses have been processed
        """

        # TODO: Take care of those functions that are already generated
        if self._next_addr is None:
            self._next_addr = self._get_min_addr()
            curr_addr = self._next_addr
        else:
            curr_addr = self._next_addr + 1

        if not self._inside_regions(curr_addr):
            curr_addr = self._next_address_in_regions(curr_addr)

        if curr_addr is None:
            l.debug("All addresses within memory regions have been scanned.")
            return None

        if self._seg_list.has_blocks:
            curr_addr = self._seg_list.next_free_pos(curr_addr)

        if alignment is not None:
            if curr_addr % alignment > 0:
                curr_addr = curr_addr - (curr_addr % alignment) + alignment

        # Make sure curr_addr exists in binary
        accepted = False
        for start, end in self._regions.iter_items():
            if start <= curr_addr < end:
                # accept
                accepted = True
                break
            if curr_addr < start:
                # accept, but we are skipping the gap
                accepted = True
                curr_addr = start
                break

        if not accepted:
            # No memory available!
            return None

        self._next_addr = curr_addr
        if self._inside_regions(curr_addr):
            l.debug("Returning a new recon address: %#x", curr_addr)
            return curr_addr

        l.debug("%#x is beyond the ending point. Returning None.", curr_addr)
        return None

    def _load_a_byte_as_int(self, addr):
        if self._base_state is not None:
            try:
                val = chr(self._base_state.mem_concrete(addr, 1, inspect=False, disable_actions=True))
            except SimValueError:
                # Not concretizable
                l.debug("Address %#x is not concretizable!", addr)
                return None
        else:
            val = self._fast_memory_load_byte(addr)
            if val is None:
                return None
        return val

    def _scan_for_printable_strings(self, start_addr):
        addr = start_addr
        sz = ""
        is_sz = True

        # Get data until we meet a null-byte
        while self._inside_regions(addr):
            l.debug("Searching address %x", addr)
            val = self._load_a_byte_as_int(addr)
            if val is None:
                break
            if val == '\x00':
                if len(sz) < 4:
                    is_sz = False
                break
            if val not in self.PRINTABLES:
                is_sz = False
                break
            sz += val
            addr += 1

        if sz and is_sz:
            l.debug("Got a string of %d chars: [%s]", len(sz), sz)
            string_length = len(sz) + 1
            return string_length

        # no string is found
        return 0

    def _scan_for_repeating_bytes(self, start_addr, repeating_byte):
        assert len(repeating_byte) == 1
        addr = start_addr

        repeating_length = 0

        while self._inside_regions(addr):
            val = self._load_a_byte_as_int(addr)
            if val is None:
                break
            if val == repeating_byte:
                repeating_length += 1
            else:
                break
            addr += 1

        if repeating_length > self.project.arch.bits / 8:  # this is pretty random
            return repeating_length
        else:
            return 0

    def _next_code_addr_core(self):
        """
        Call _next_unscanned_addr() first to get the next address that is not scanned. Then check if data locates at
        that address seems to be code or not. If not, we'll continue to for the next un-scanned address.
        """

        next_addr = self._next_unscanned_addr()
        if next_addr is None:
            return None

        start_addr = next_addr

        while True:
            string_length = self._scan_for_printable_strings(start_addr)
            if string_length:
                self._seg_list.occupy(start_addr, string_length, "string")
                start_addr += string_length

            if self.project.arch.name in ('X86', 'AMD64'):
                cc_length = self._scan_for_repeating_bytes(start_addr, '\xcc')
                if cc_length:
                    self._seg_list.occupy(start_addr, cc_length, "alignment")
                    start_addr += cc_length
            else:
                cc_length = 0

            zeros_length = self._scan_for_repeating_bytes(start_addr, '\x00')
            if zeros_length:
                self._seg_list.occupy(start_addr, zeros_length, "alignment")
                start_addr += zeros_length
            start_addr += zeros_length

            if string_length == 0 and cc_length == 0 and zeros_length == 0:
                # umm now it's probably code
                break

        instr_alignment = self._initial_state.arch.instruction_alignment
        if start_addr % instr_alignment > 0:
            # occupy those few bytes
            self._seg_list.occupy(start_addr, instr_alignment - (start_addr % instr_alignment), 'alignment')
            start_addr = start_addr - start_addr % instr_alignment + \
                         instr_alignment

        return start_addr

    def _next_code_addr(self):

        while True:
            addr = self._next_code_addr_core()
            if addr is None:
                return None

            # if the new address is already occupied
            if not self._seg_list.is_occupied(addr):
                return addr


    # Overriden methods from ForwardAnalysis

    def _job_key(self, job):
        return job.addr

    def _pre_analysis(self):
        # Initialize variables used during analysis
        self._pending_jobs = [ ]
        self._traced_addresses = set()
        self._function_returns = defaultdict(list)

        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        self._function_exits = defaultdict(set)

        self._initialize_cfg()

        # Create an initial state. Store it to self so we can use it globally.
        self._initial_state = self.project.factory.blank_state(mode="fastpath")
        initial_options = self._initial_state.options - {o.TRACK_CONSTRAINTS} - o.refs
        initial_options |= {o.SUPER_FASTPATH}
        # initial_options.remove(o.COW_STATES)
        self._initial_state.options = initial_options

        starting_points = set()

        # clear all existing functions
        self.kb.functions.clear()

        if self._use_symbols:
            starting_points |= self._function_addresses_from_symbols

        if self._extra_function_starts:
            starting_points |= set(self._extra_function_starts)

        # Sort it
        starting_points = sorted(list(starting_points), reverse=True)

        if self._start_at_entry and self.project.entry is not None and self._inside_regions(self.project.entry) and \
                self.project.entry not in starting_points:
            # make sure self.project.entry is inserted
            starting_points += [ self.project.entry ]

        # Create jobs for all starting points
        for sp in starting_points:
            job = CFGJob(sp, sp, 'Ijk_Boring')
            self._insert_job(job)
            # register the job to function `sp`
            self._register_analysis_job(sp, job)

        self._changed_functions = set()

        self._nodes = {}
        self._nodes_by_addr = defaultdict(list)

        if self._use_function_prologues:
            self._function_prologue_addrs = sorted(self._func_addrs_from_prologues())
            # make a copy of those prologue addresses, so that we can pop from the list
            self._remaining_function_prologue_addrs = self._function_prologue_addrs[::]

            # make function_prologue_addrs a set for faster lookups
            self._function_prologue_addrs = set(self._function_prologue_addrs)

    def _pre_job_handling(self, job):  # pylint:disable=arguments-differ
        """
        Some pre job-processing tasks, like update progress bar.

        :param CFGJob job: The CFGJob instance.
        :return: None
        """

        # a new entry is picked. Deregister it
        self._deregister_analysis_job(job.func_addr, job)

        # Do not calculate progress if the user doesn't care about the progress at all
        if self._show_progressbar or self._progress_callback:
            max_percentage_stage_1 = 50.0
            percentage = self._seg_list.occupied_size * max_percentage_stage_1 / self._regions_size
            if percentage > max_percentage_stage_1:
                percentage = max_percentage_stage_1

            self._update_progress(percentage)

    def _intra_analysis(self):
        pass

    def _get_successors(self, job):  # pylint:disable=arguments-differ

        current_function_addr = job.func_addr
        addr = job.addr
        jumpkind = job.jumpkind
        src_node = job.src_node
        src_stmt_idx = job.src_stmt_idx
        src_ins_addr = job.src_ins_addr

        if current_function_addr != -1:
            l.debug("Tracing new exit %#x in function %#x",
                    addr, current_function_addr)
        else:
            l.debug("Tracing new exit %#x", addr)

        jobs = self._scan_block(addr, current_function_addr, jumpkind, src_node, src_ins_addr, src_stmt_idx)

        l.debug("... got %d jobs: %s", len(jobs), jobs)

        for job_ in jobs:  # type: CFGJob
            # register those jobs
            self._register_analysis_job(job_.func_addr, job_)

        return jobs

    def _handle_successor(self, job, successor, successors):
        return [ successor ]

    def _merge_jobs(self, *jobs):
        pass

    def _widen_jobs(self, *jobs):
        pass

    def _post_process_successors(self, addr, successors):

        if self.project.arch.name in ('ARMEL', 'ARMHF') and addr % 2 == 1:
            # we are in thumb mode. filter successors
            successors = self._arm_thumb_filter_jump_successors(addr,
                                                                successors,
                                                                lambda tpl: tpl[1],
                                                                lambda tpl: tpl[0]
                                                                )

        return successors

    def _post_job_handling(self, job, new_jobs, successors):
        pass

    def _job_queue_empty(self):

        if self._pending_jobs:
            # look for a job that comes from a function that must return
            # if we can find one, just use it
            job_index = None
            for i, job in enumerate(self._pending_jobs):
                src_func_addr = job.returning_source
                if src_func_addr is None or src_func_addr not in self.kb.functions:
                    continue
                function = self.kb.functions[src_func_addr]
                if function.returning is True:
                    job_index = i
                    break

            if job_index is not None:
                self._insert_job(self._pending_jobs[job_index])
                del self._pending_jobs[job_index]
                return

        # did we finish analyzing any function?
        # fill in self._completed_functions
        self._make_completed_functions()

        # analyze function features, most importantly, whether each function returns or not
        self._analyze_all_function_features()

        if self._pending_jobs:
            self._clean_pending_exits()

        # Clear _changed_functions set
        self._changed_functions = set()

        if self._pending_jobs:
            self._insert_job(self._pending_jobs[0])
            del self._pending_jobs[0]
            return

        if self._use_function_prologues and self._remaining_function_prologue_addrs:
            while self._remaining_function_prologue_addrs:
                prolog_addr = self._remaining_function_prologue_addrs[0]
                self._remaining_function_prologue_addrs = self._remaining_function_prologue_addrs[1:]
                if self._seg_list.is_occupied(prolog_addr):
                    continue

                job = CFGJob(prolog_addr, prolog_addr, 'Ijk_Boring')
                self._insert_job(job)
                self._register_analysis_job(prolog_addr, job)
                return

        # Try to see if there is any indirect jump left to be resolved
        if self._resolve_indirect_jumps and self._indirect_jumps_to_resolve:
            jump_targets = list(set(self._process_indirect_jumps()))

            for addr, func_addr, source_addr, jumpkind in jump_targets:
                to_outside = addr in self.functions

                if not to_outside:
                    to_outside = not self._addrs_belong_to_same_section(source_addr, addr)

                r = self._function_add_transition_edge(addr, self._nodes[source_addr], func_addr, to_outside=to_outside)
                if r:
                    # TODO: get a better estimate of the function address
                    target_func_addr = func_addr if not to_outside else addr
                    job = CFGJob(addr, target_func_addr, jumpkind, last_addr=source_addr,
                                 src_node=self._nodes[source_addr],
                                 src_stmt_idx=None,
                                 )
                    self._insert_job(job)
                    self._register_analysis_job(target_func_addr, job)

            if self._job_info_queue:
                return

        if self._force_complete_scan:
            addr = self._next_code_addr()

            if addr is not None:
                job = CFGJob(addr, addr, "Ijk_Boring", last_addr=None)
                self._insert_job(job)
                self._register_analysis_job(addr, job)

    def _post_analysis(self):

        self._analyze_all_function_features()

        # Scan all functions, and make sure all fake ret edges are either confirmed or removed
        for f in self.functions.values():
            all_edges = f.transition_graph.edges(data=True)

            callsites_to_functions = defaultdict(list) # callsites to functions mapping

            for src, dst, data in all_edges:
                if 'type' in data:
                    if data['type'] == 'call':
                        callsites_to_functions[src.addr].append(dst.addr)

            edges_to_remove = [ ]
            for src, dst, data in all_edges:
                if 'type' in data:
                    if data['type'] == 'fake_return' and 'confirmed' not in data:

                        # Get all possible functions being called here
                        target_funcs = [ self.functions.function(addr=func_addr)
                                         for func_addr in callsites_to_functions[src.addr]
                                         ]
                        if target_funcs and all([ t is not None and t.returning is False for t in target_funcs ]):
                            # Remove this edge
                            edges_to_remove.append((src, dst))
                        else:
                            # Mark this edge as confirmed
                            f._confirm_fakeret(src, dst)

            for edge in edges_to_remove:
                f.transition_graph.remove_edge(*edge)

            # Clear the cache
            f._local_transition_graph = None

        # Scan all functions, and make sure .returning for all functions are either True or False
        for f in self.functions.values():
            if f.returning is None:
                f.returning = len(f.endpoints) > 0  # pylint:disable=len-as-condition

        if self.project.arch.name in ('X86', 'AMD64', 'MIPS32'):
            self._remove_redundant_overlapping_blocks()

        if self._normalize:
            # Normalize the control flow graph first before rediscovering all functions
            self.normalize()

        self.make_functions()
        # optional: remove functions that must be alignments
        self.remove_function_alignments()

        # make return edges
        self._make_return_edges()

        if self.project.loader.main_object.sections:
            # this binary has sections
            # make sure we have data entries assigned at the beginning of each data section
            for sec in self.project.loader.main_object.sections:
                if sec.memsize > 0 and not sec.is_executable and sec.is_readable:
                    for seg in self.project.loader.main_object.segments:
                        if seg.vaddr <= sec.vaddr < seg.vaddr + seg.memsize:
                            break
                    else:
                        continue

                    if sec.vaddr not in self.memory_data:
                        self.memory_data[sec.vaddr] = MemoryData(sec.vaddr, 0, 'unknown', None, None, None, None)

        r = True
        while r:
            r = self._tidy_data_references()

        CFGBase._post_analysis(self)

        self._finish_progress()

    # Methods to get start points for scanning

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
        # TODO: We shouldn't directly access the _memory of main_object. An interface
        # TODO: to that would be awesome.

        strides = self._binary.memory.stride_repr

        unassured_functions = []

        for start_, _, bytes_ in strides:
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        if self._addr_in_exec_memory_regions(position):
                            unassured_functions.append(AT.from_rva(position, self._binary).to_mva())

        return unassured_functions

    # Basic block scanning

    def _scan_block(self, addr, current_function_addr, previous_jumpkind, previous_src_node, previous_src_ins_addr,
                    previous_src_stmt_idx):
        """
        Scan a basic block starting at a specific address

        :param int addr: The address to begin scanning
        :param int current_function_addr: Address of the current function
        :param str previous_jumpkind: The jumpkind of the edge going to this node
        :param CFGNode previous_src_node: The previous CFGNode
        :return: a list of successors
        :rtype: list
        """

        # Fix the function address
        # This is for rare cases where we cannot successfully determine the end boundary of a previous function, and
        # as a consequence, our analysis mistakenly thinks the previous function goes all the way across the boundary,
        # resulting the missing of the second function in function manager.
        if addr in self._function_addresses_from_symbols:
            current_function_addr = addr

        if self._addr_hooked_or_syscall(addr):
            entries = self._scan_procedure(addr, current_function_addr, previous_jumpkind, previous_src_node,
                                           previous_src_ins_addr, previous_src_stmt_idx)

        else:
            entries = self._scan_irsb(addr, current_function_addr, previous_jumpkind, previous_src_node,
                                      previous_src_ins_addr, previous_src_stmt_idx)

        return entries

    def _scan_procedure(self, addr, current_function_addr, previous_jumpkind, previous_src_node, previous_src_ins_addr,
                        previous_src_stmt_idx):
        """
        Checks the hooking procedure for this address searching for new static
        exit points to add to successors (generating entries for them)
        if this address has not been traced before. Updates previous CFG nodes
        with edges.

        :param int addr: The address to begin scanning
        :param int current_function_addr: Address of the current function
        :param str previous_jumpkind: The jumpkind of the edge going to this node
        :param CFGNode previous_src_node: The previous CFGNode
        :param int previous_src_stmt_idx: The previous ID of the statement.
        :return: List of successors
        :rtype: list
        """
        try:
            if self.project.is_hooked(addr):
                procedure = self.project.hooked_by(addr)
                name = procedure.display_name
            else:
                procedure = self.project.simos.syscall_from_addr(addr)
                name = procedure.display_name

            if addr not in self._nodes:
                cfg_node = CFGNode(addr, 0, self, function_address=current_function_addr,
                                   simprocedure_name=name,
                                   no_ret=procedure.NO_RET,
                                   block_id=addr,
                                   )

                self._nodes[addr] = cfg_node
                self._nodes_by_addr[addr].append(cfg_node)

            else:
                cfg_node = self._nodes[addr]

        except (SimMemoryError, SimEngineError):
            return [ ]

        self._graph_add_edge(cfg_node, previous_src_node, previous_jumpkind, previous_src_ins_addr,
                             previous_src_stmt_idx
                             )
        self._function_add_node(addr, current_function_addr)
        self._changed_functions.add(current_function_addr)

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(addr)

        entries = [ ]

        if procedure.ADDS_EXITS:
            # Get two blocks ahead
            grandparent_nodes = list(self.graph.predecessors(previous_src_node))
            if not grandparent_nodes:
                l.warning("%s is supposed to yield new exits, but it fails to do so.", name)
                return [ ]
            blocks_ahead = [
                self._lift(grandparent_nodes[0].addr).vex,
                self._lift(previous_src_node.addr).vex,
            ]
            procedure.project = self.project
            procedure.arch = self.project.arch
            new_exits = procedure.static_exits(blocks_ahead)

            for addr_, jumpkind in new_exits:
                if isinstance(addr_, claripy.ast.BV) and not addr_.symbolic:
                    addr_ = addr_._model_concrete.value
                if not isinstance(addr_, (int, long)):
                    continue
                entries += self._create_jobs(addr_, jumpkind, current_function_addr, None, addr_, cfg_node, None,
                                             None
                                             )

        if not procedure.NO_RET:
            # it returns
            cfg_node.has_return = True
            self._function_exits[current_function_addr].add(addr)
            self._function_add_return_site(addr, current_function_addr)

        return entries

    def _scan_irsb(self, addr, current_function_addr, previous_jumpkind, previous_src_node, previous_src_ins_addr,
                   previous_src_stmt_idx):
        """
        Generate a list of successors (generating them each as entries) to IRSB.
        Updates previous CFG nodes with edges.

        :param int addr: The address to begin scanning
        :param int current_function_addr: Address of the current function
        :param str previous_jumpkind: The jumpkind of the edge going to this node
        :param CFGNode previous_src_node: The previous CFGNode
        :param int previous_src_stmt_idx: The previous ID of the statement
        :return: a list of successors
        :rtype: list
        """

        addr, function_addr, cfg_node, irsb = self._generate_cfgnode(addr, current_function_addr)

        # function_addr and current_function_addr can be different. e.g. when tracing an optimized tail-call that jumps
        # into another function that has been identified before.

        if cfg_node is None:
            # exceptions occurred, or we cannot get a CFGNode for other reasons
            return [ ]

        self._graph_add_edge(cfg_node, previous_src_node, previous_jumpkind, previous_src_ins_addr,
                             previous_src_stmt_idx
                             )
        self._function_add_node(addr, function_addr)
        self._changed_functions.add(current_function_addr)

        # If we have traced it before, don't trace it anymore
        aligned_addr = ((addr >> 1) << 1) if self.project.arch.name in ('ARMLE', 'ARMHF') else addr
        if aligned_addr in self._traced_addresses:
            # the address has been traced before
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(aligned_addr)

        # irsb cannot be None here
        # assert irsb is not None

        # IRSB is only used once per CFGNode. We should be able to clean up the CFGNode here in order to save memory
        cfg_node.irsb = None

        self._process_block_arch_specific(addr, irsb, function_addr)

        # Scan the basic block to collect data references
        if self._collect_data_ref:
            self._collect_data_references(irsb, addr)

        # Get all possible successors
        irsb_next, jumpkind = irsb.next, irsb.jumpkind
        successors = [ ]

        last_ins_addr = None
        ins_addr = addr
        for i, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.IRStmt.Exit):
                successors.append((i,
                                   last_ins_addr if self.project.arch.branch_delay_slot else ins_addr,
                                   stmt.dst,
                                   stmt.jumpkind
                                   )
                                  )
            elif isinstance(stmt, pyvex.IRStmt.IMark):
                last_ins_addr = ins_addr
                ins_addr = stmt.addr + stmt.delta

        successors.append(('default',
                           last_ins_addr if self.project.arch.branch_delay_slot else ins_addr, irsb_next, jumpkind)
                          )

        entries = [ ]

        successors = self._post_process_successors(addr, successors)

        # Process each successor
        for suc in successors:
            stmt_idx, ins_addr, target, jumpkind = suc

            entries += self._create_jobs(target, jumpkind, function_addr, irsb, addr, cfg_node, ins_addr,
                                         stmt_idx
                                         )

        return entries

    def _create_jobs(self, target, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx,
                     fast_indirect_jump_resolution=True):
        """
        Given a node and details of a successor, makes a list of CFGJobs
        and if it is a call or exit marks it appropriately so in the CFG

        :param int target:          Destination of the resultant job
        :param str jumpkind:        The jumpkind of the edge going to this node
        :param int current_function_addr: Address of the current function
        :param pyvex.IRSB irsb:     IRSB of the predecessor node
        :param int addr:            The predecessor address
        :param CFGNode cfg_node:    The CFGNode of the predecessor node
        :param int ins_addr:        Address of the source instruction.
        :param int stmt_idx:        ID of the source statement.
        :return:                    a list of CFGJobs
        :rtype:                     list
        """

        if type(target) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
            target_addr = target.con.value
        elif type(target) in (pyvex.IRConst.U32, pyvex.IRConst.U64):  # pylint: disable=unidiomatic-typecheck
            target_addr = target.value
        elif type(target) in (int, long):  # pylint: disable=unidiomatic-typecheck
            target_addr = target
        else:
            target_addr = None

        jobs = [ ]

        if target_addr is None and (
                        jumpkind in ('Ijk_Boring', 'Ijk_Call') or jumpkind.startswith('Ijk_Sys'))\
                and fast_indirect_jump_resolution:
            # try resolving it fast
            resolved, resolved_targets = self._resolve_indirect_jump_timelessly(addr, irsb, current_function_addr,
                                                                                jumpkind
                                                                                )
            if resolved:
                for t in resolved_targets:
                    ent = self._create_jobs(t, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr,
                                            stmt_idx, fast_indirect_jump_resolution=False)
                    jobs.extend(ent)
                return jobs

        # pylint: disable=too-many-nested-blocks
        if jumpkind == 'Ijk_Boring':
            if target_addr is not None:

                # if the target address is at another section, it has to be jumping to a new function
                if not self._addrs_belong_to_same_section(addr, target_addr):
                    target_func_addr = target_addr
                    to_outside = True
                else:
                    # it might be a jumpout
                    target_func_addr = None
                    if target_addr in self._traced_addresses:
                        node = self.get_any_node(target_addr)
                        if node is not None:
                            target_func_addr = node.function_address
                    if target_func_addr is None:
                        target_func_addr = current_function_addr

                    to_outside = not target_func_addr == current_function_addr

                r = self._function_add_transition_edge(target_addr, cfg_node, current_function_addr, ins_addr=ins_addr,
                                                       stmt_idx=stmt_idx, to_outside=to_outside
                                                       )

                if not r:
                    if cfg_node is not None:
                        l.debug("An angr exception occurred when adding a transition from %#x to %#x. "
                                "Ignore this successor.",
                                cfg_node.addr,
                                target_addr
                                )
                    else:
                        l.debug("SimTranslationError occurred when creating a new entry to %#x. "
                                "Ignore this successor.",
                                target_addr
                                )
                    return []

                ce = CFGJob(target_addr, target_func_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                            src_ins_addr=ins_addr, src_stmt_idx=stmt_idx)
                jobs.append(ce)

            else:
                l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)
                # Add it to our set. Will process it later if user allows.
                # Create an IndirectJump instance
                if addr not in self.indirect_jumps:
                    tmp_statements = irsb.statements if stmt_idx == 'default' else irsb.statements[ : stmt_idx]
                    ins_addr = next(iter(stmt.addr for stmt in reversed(tmp_statements)
                                         if isinstance(stmt, pyvex.IRStmt.IMark)), None
                                    )
                    ij = IndirectJump(addr, ins_addr, current_function_addr, jumpkind, stmt_idx, resolved_targets=[ ])
                    self.indirect_jumps[addr] = ij
                else:
                    ij = self.indirect_jumps[addr]

                # TODO: revisit the logic here
                # TODO: - put the indirect jump reusing logic into a separate method

                if ij.resolved_targets:
                    # has been resolved before
                    # directly create CFGJobs
                    for resolved_target in ij.resolved_targets:
                        ce = CFGJob(resolved_target, resolved_target, jumpkind, last_addr=resolved_target,
                                    src_node=cfg_node, src_stmt_idx=stmt_idx, src_ins_addr=ins_addr)
                        jobs.append(ce)

                        self._function_add_call_edge(resolved_target, None, None, resolved_target,
                                                     stmt_idx=stmt_idx, ins_addr=ins_addr
                                                     )
                else:
                    resolved_as_plt = False

                    if irsb and self._heuristic_plt_resolving:
                        # Test it on the initial state. Does it jump to a valid location?
                        # It will be resolved only if this is a .plt entry
                        resolved_as_plt = self._resolve_plt(addr, irsb, ij)

                        if resolved_as_plt:

                            jump_target = next(iter(ij.resolved_targets))
                            target_func_addr = jump_target  # TODO: FIX THIS

                            r = self._function_add_transition_edge(jump_target, cfg_node, current_function_addr,
                                                                   ins_addr=ins_addr, stmt_idx=stmt_idx,
                                                                   to_outside=True
                                                                   )
                            if r:
                                ce = CFGJob(jump_target, target_func_addr, jumpkind, last_addr=jump_target,
                                            src_node=cfg_node, src_stmt_idx=stmt_idx, src_ins_addr=ins_addr)
                                jobs.append(ce)

                                self._function_add_call_edge(jump_target, None, None, target_func_addr,
                                                             stmt_idx=stmt_idx, ins_addr=ins_addr
                                                             )
                                resolved_as_plt = True

                    if resolved_as_plt:
                        # has been resolved as a PLT entry. Remove it from indirect_jumps_to_resolve
                        if ij.addr in self._indirect_jumps_to_resolve:
                            self._indirect_jumps_to_resolve.remove(ij.addr)
                            self._deregister_analysis_job(current_function_addr, ij)
                    else:
                        # add it to indirect_jumps_to_resolve
                        self._indirect_jumps_to_resolve.add(ij)

                        # register it as a job for the current function
                        self._register_analysis_job(current_function_addr, ij)

        elif jumpkind == 'Ijk_Call' or jumpkind.startswith("Ijk_Sys"):
            is_syscall = jumpkind.startswith("Ijk_Sys")

            if target_addr is not None:
                jobs += self._create_job_call(addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr,
                                              target_addr, jumpkind, is_syscall=is_syscall
                                              )

            else:
                l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)
                # Add it to our set. Will process it later if user allows.

                if addr not in self.indirect_jumps:
                    tmp_statements = irsb.statements if stmt_idx == 'default' else irsb.statements[: stmt_idx]
                    if self.project.arch.branch_delay_slot:
                        ins_addr = next(itertools.islice(iter(stmt.addr for stmt in reversed(tmp_statements)
                                             if isinstance(stmt, pyvex.IRStmt.IMark)), 1, None
                                        ), None)
                    else:
                        ins_addr = next(iter(stmt.addr for stmt in reversed(tmp_statements)
                                          if isinstance(stmt, pyvex.IRStmt.IMark)), None
                                        )
                    ij = IndirectJump(addr, ins_addr, current_function_addr, jumpkind, stmt_idx,
                                      resolved_targets=[])
                    self.indirect_jumps[addr] = ij
                else:
                    ij = self.indirect_jumps[addr]

                self._indirect_jumps_to_resolve.add(ij)
                self._register_analysis_job(current_function_addr, ij)

                self._create_job_call(addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr, None,
                                      jumpkind, is_syscall=is_syscall
                                      )

        elif jumpkind == "Ijk_Ret":
            if current_function_addr != -1:
                self._function_exits[current_function_addr].add(addr)
                self._function_add_return_site(addr, current_function_addr)

            cfg_node.has_return = True

        else:
            # TODO: Support more jumpkinds
            l.debug("Unsupported jumpkind %s", jumpkind)

        return jobs

    def _create_job_call(self, addr, irsb, cfg_node, stmt_idx, ins_addr, current_function_addr, target_addr, jumpkind,
                         is_syscall=False):
        """
        Generate a CFGJob for target address, also adding to _pending_entries
        if returning to succeeding position (if irsb arg is populated)

        :param int addr:            Address of the predecessor node
        :param pyvex.IRSB irsb:     IRSB of the predecessor node
        :param CFGNode cfg_node:    The CFGNode instance of the predecessor node
        :param int stmt_idx:        ID of the source statement
        :param int ins_addr:        Address of the source instruction
        :param int current_function_addr: Address of the current function
        :param int target_addr:     Destination of the call
        :param str jumpkind:        The jumpkind of the edge going to this node
        :param bool is_syscall:     Is the jump kind (and thus this) a system call
        :return:                    A list of CFGJobs
        :rtype:                     list
        """

        jobs = [ ]

        if is_syscall:
            # Fix the target_addr for syscalls
            tmp_state = self.project.factory.blank_state(mode="fastpath", addr=cfg_node.addr)
            succ = self.project.factory.successors(tmp_state).flat_successors[0]
            syscall_stub = self.project.simos.syscall(succ)
            if syscall_stub: # can be None if simos is not a subclass of SimUserspac
                syscall_addr = self.project.simos.syscall(succ).addr
                target_addr = syscall_addr
            else:
                target_addr = self._unresolvable_target_addr

        new_function_addr = target_addr
        if irsb is None:
            return_site = None
        else:
            return_site = addr + irsb.size  # We assume the program will always return to the succeeding position

        if new_function_addr is not None:
            r = self._function_add_call_edge(new_function_addr, cfg_node, return_site, current_function_addr,
                                             syscall=is_syscall, stmt_idx=stmt_idx, ins_addr=ins_addr)
            if not r:
                return [ ]

        if new_function_addr is not None:
            # Keep tracing from the call
            ce = CFGJob(target_addr, new_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                        src_stmt_idx=stmt_idx, src_ins_addr=ins_addr, syscall=is_syscall)
            jobs.append(ce)

        if return_site is not None:
            # Also, keep tracing from the return site
            ce = CFGJob(return_site, current_function_addr, 'Ijk_FakeRet', last_addr=addr, src_node=cfg_node,
                        src_stmt_idx=stmt_idx, src_ins_addr=ins_addr, returning_source=new_function_addr,
                        syscall=is_syscall)
            self._pending_jobs.append(ce)
            # register this job to this function
            self._register_analysis_job(current_function_addr, ce)

        if new_function_addr is not None:
            callee_function = self.kb.functions.function(addr=new_function_addr, syscall=is_syscall)

            if callee_function.returning is True:
                if return_site is not None:
                    self._function_add_fakeret_edge(return_site, cfg_node, current_function_addr,
                                                    confirmed=True)
                    self._function_add_return_edge(new_function_addr, return_site, current_function_addr)
            elif callee_function.returning is False:
                # The function does not return - there is no fake ret edge
                pass
            else:
                if return_site is not None:
                    self._function_add_fakeret_edge(return_site, cfg_node, current_function_addr,
                                                    confirmed=None)
                    fr = FunctionReturn(new_function_addr, current_function_addr, addr, return_site)
                    if fr not in self._function_returns[new_function_addr]:
                        self._function_returns[new_function_addr].append(fr)

        return jobs

    # Data reference processing

    def _collect_data_references(self, irsb, irsb_addr):
        """
        Unoptimises IRSB and _add_data_reference's for individual statements or
        for parts of statements (e.g. Store)

        :param pyvex.IRSB irsb: Block to scan for data references
        :param int irsb_addr: Address of block
        :return: None
        """

        if self.project.arch.name in ('X86', 'AMD64'):
            # first pass to see if there are any cross-statement optimizations. if so, we relift the basic block with
            # optimization level 0 to preserve as much constant references as possible
            empty_insn = False
            all_statements = len(irsb.statements)
            for i, stmt in enumerate(irsb.statements[:-1]):
                if isinstance(stmt, pyvex.IRStmt.IMark) and (
                        isinstance(irsb.statements[i + 1], pyvex.IRStmt.IMark) or
                        (i + 2 < all_statements and isinstance(irsb.statements[i + 2], pyvex.IRStmt.IMark))
                ):
                    # this is a very bad check...
                    # the correct way to do it is to disable cross-instruction optimization in VEX
                    empty_insn = True
                    break

            if empty_insn:
                # make sure opt_level is 0
                irsb = self._lift(addr=irsb_addr, size=irsb.size, opt_level=0).vex

        # for each statement, collect all constants that are referenced or used.
        self._collect_data_references_core(irsb, irsb_addr)

    def _collect_data_references_core(self, irsb, irsb_addr):

        # helper methods
        def _process(irsb_, stmt_, stmt_idx_, data_, insn_addr, next_insn_addr, data_size=None, data_type=None):
            """
            Helper method used for calling _add_data_reference after checking
            for manipulation of constants

            :param pyvex.IRSB irsb_: Edited block (as might be de-optimised)
            :param pyvex.IRStmt.* stmt_: Statement
            :param int stmt_idx_: Statement ID
            :param data_: data manipulated by statement
            :param int insn_addr: instruction address
            :param int next_insn_addr: next instruction address
            :param data_size: Size of the data being manipulated
            :param str data_type: Type of the data being manipulated
            :return: None
            """
            if type(data_) is pyvex.expr.Const:  # pylint: disable=unidiomatic-typecheck
                val = data_.con.value
            elif type(data_) in (int, long):
                val = data_
            else:
                return

            if val != next_insn_addr:
                self._add_data_reference(irsb_, irsb_addr, stmt_, stmt_idx_, insn_addr, val,
                                         data_size=data_size, data_type=data_type
                                         )

        # get all instruction addresses
        instr_addrs = [ (i.addr + i.delta) for i in irsb.statements if isinstance(i, pyvex.IRStmt.IMark) ]

        # for each statement, collect all constants that are referenced or used.
        instr_addr = None
        next_instr_addr = None
        for stmt_idx, stmt in enumerate(irsb.statements):
            if type(stmt) is pyvex.IRStmt.IMark:  # pylint: disable=unidiomatic-typecheck
                instr_addr = instr_addrs[0]
                instr_addrs = instr_addrs[1 : ]
                next_instr_addr = instr_addrs[0] if instr_addrs else None

            elif type(stmt) is pyvex.IRStmt.WrTmp:  # pylint: disable=unidiomatic-typecheck
                if type(stmt.data) is pyvex.IRExpr.Load:  # pylint: disable=unidiomatic-typecheck
                    # load
                    # e.g. t7 = LDle:I64(0x0000000000600ff8)
                    size = stmt.data.result_size(irsb.tyenv) / 8 # convert to bytes
                    _process(irsb, stmt, stmt_idx, stmt.data.addr, instr_addr, next_instr_addr,
                             data_size=size, data_type='integer'
                             )

                elif type(stmt.data) in (pyvex.IRExpr.Binop, ):  # pylint: disable=unidiomatic-typecheck

                    # rip-related addressing
                    if stmt.data.op in ('Iop_Add32', 'Iop_Add64') and \
                            all(type(arg) is pyvex.expr.Const for arg in stmt.data.args):
                        # perform the addition
                        loc = stmt.data.args[0].con.value + stmt.data.args[1].con.value
                        _process(irsb, stmt, stmt_idx, loc, instr_addr, next_instr_addr)

                    else:
                        # binary operation
                        for arg in stmt.data.args:
                            _process(irsb, stmt, stmt_idx, arg, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
                    _process(irsb, stmt, stmt_idx, stmt.data, instr_addr, next_instr_addr)

                elif type(stmt.data) is pyvex.IRExpr.ITE:
                    for child_expr in stmt.data.child_expressions:
                        _process(irsb, stmt, stmt_idx, child_expr, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Put:  # pylint: disable=unidiomatic-typecheck
                # put
                # e.g. PUT(rdi) = 0x0000000000400714
                if stmt.offset not in (self._initial_state.arch.ip_offset, ):
                    _process(irsb, stmt, stmt_idx, stmt.data, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Store:  # pylint: disable=unidiomatic-typecheck
                # store addr
                _process(irsb, stmt, stmt_idx, stmt.addr, instr_addr, next_instr_addr)
                # store data
                _process(irsb, stmt, stmt_idx, stmt.data, instr_addr, next_instr_addr)

            elif type(stmt) is pyvex.IRStmt.Dirty:

                _process(irsb, stmt, stmt_idx, stmt.mAddr, instr_addr, next_instr_addr,
                         data_size=stmt.mSize,
                         data_type='fp'
                         )

    def _add_data_reference(self, irsb, irsb_addr, stmt, stmt_idx, insn_addr, data_addr,  # pylint: disable=unused-argument
                            data_size=None, data_type=None):
        """
        Checks addresses are in the correct segments and creates or updates
        MemoryData in _memory_data as appropriate, labelling as segment
        boundaries or data type

        :param pyvex.IRSB irsb: irsb
        :param int irsb_addr: irsb address
        :param pyvex.IRStmt.* stmt: Statement
        :param int stmt_idx: Statement ID
        :param int insn_addr: instruction address
        :param data_addr: address of data manipulated by statement
        :param data_size: Size of the data being manipulated
        :param str data_type: Type of the data being manipulated
        :return: None
        """

        # Make sure data_addr is within a valid memory range
        if not self._addr_belongs_to_segment(data_addr):

            # data might be at the end of some section or segment...
            # let's take a look
            for segment in self.project.loader.main_object.segments:
                if segment.vaddr + segment.memsize == data_addr:
                    # yeah!
                    if data_addr not in self._memory_data:
                        data = MemoryData(data_addr, 0, 'segment-boundary', irsb, irsb_addr, stmt, stmt_idx,
                                          insn_addr=insn_addr
                                          )
                        self._memory_data[data_addr] = data
                    else:
                        if self._extra_cross_references:
                            self._memory_data[data_addr].add_ref(irsb_addr, stmt_idx, insn_addr)
                    break

            return

        if data_addr not in self._memory_data:
            if data_type is not None and data_size is not None:
                data = MemoryData(data_addr, data_size, data_type, irsb, irsb_addr, stmt, stmt_idx,
                                  insn_addr=insn_addr, max_size=data_size
                                  )
            else:
                data = MemoryData(data_addr, 0, 'unknown', irsb, irsb_addr, stmt, stmt_idx, insn_addr=insn_addr)
            self._memory_data[data_addr] = data
        else:
            if self._extra_cross_references:
                self._memory_data[data_addr].add_ref(irsb_addr, stmt_idx, insn_addr)

        self.insn_addr_to_memory_data[insn_addr] = self._memory_data[data_addr]

    def _tidy_data_references(self):
        """

        :return: True if new data entries are found, False otherwise.
        :rtype: bool
        """

        # Make sure all memory data entries cover all data sections
        keys = sorted(self._memory_data.iterkeys())
        for i, data_addr in enumerate(keys):
            data = self._memory_data[data_addr]
            if self._addr_in_exec_memory_regions(data.address):
                # TODO: Handle data among code regions (or executable regions)
                pass
            else:
                if i + 1 != len(keys):
                    next_data_addr = keys[i + 1]
                else:
                    next_data_addr = None

                # goes until the end of the section/segment
                # TODO: the logic needs more testing

                obj = self.project.loader.find_object_containing(data_addr)
                sec = self._addr_belongs_to_section(data_addr)
                next_sec_addr = None
                if sec is not None:
                    last_addr = sec.vaddr + sec.memsize
                else:
                    # it does not belong to any section. what's the next adjacent section? any memory data does not go
                    # beyong section boundaries
                    next_sec = self._addr_next_section(data_addr)
                    if next_sec is not None:
                        next_sec_addr = next_sec.vaddr

                    seg = self._addr_belongs_to_segment(data_addr)
                    if seg is not None:
                        last_addr = seg.vaddr + seg.memsize
                    else:
                        # We got an address that is not inside the current binary...
                        l.warning('_tidy_data_references() sees an address %#08x that does not belong to any '
                                  'section or segment.', data_addr
                                  )
                        last_addr = None

                if next_data_addr is None:
                    boundary = last_addr
                elif last_addr is None:
                    boundary = next_data_addr
                else:
                    boundary = min(last_addr, next_data_addr)

                if next_sec_addr is not None:
                    boundary = min(boundary, next_sec_addr)

                if boundary is not None:
                    data.max_size = boundary - data_addr

        keys = sorted(self._memory_data.iterkeys())

        new_data_found = False

        i = 0
        # pylint:disable=too-many-nested-blocks
        while i < len(keys):
            data_addr = keys[i]
            i += 1

            memory_data = self._memory_data[data_addr]

            if memory_data.sort in ('segment-boundary', ):
                continue

            content_holder = [ ]

            # let's see what sort of data it is
            if memory_data.sort in ('unknown', None) or \
                    (memory_data.sort == 'integer' and memory_data.size == self.project.arch.bits / 8):
                data_type, data_size = self._guess_data_type(memory_data.irsb, memory_data.irsb_addr,
                                                             memory_data.stmt_idx, data_addr, memory_data.max_size,
                                                             content_holder=content_holder
                                                             )
            else:
                data_type, data_size = memory_data.sort, memory_data.size

            if data_type is not None:
                memory_data.size = data_size
                memory_data.sort = data_type

                if len(content_holder) == 1:
                    memory_data.content = content_holder[0]

                if memory_data.size > 0 and memory_data.size < memory_data.max_size:
                    # Create another memory_data object to fill the gap
                    new_addr = data_addr + memory_data.size
                    new_md = MemoryData(new_addr, None, None, None, None, None, None,
                                        max_size=memory_data.max_size - memory_data.size)
                    self._memory_data[new_addr] = new_md
                    keys.insert(i, new_addr)

                if data_type == 'pointer-array':
                    # make sure all pointers are identified
                    pointer_size = self.project.arch.bits / 8

                    for j in xrange(0, data_size, pointer_size):
                        ptr = self._fast_memory_load_pointer(data_addr + j)

                        # is this pointer coming from the current binary?
                        obj = self.project.loader.find_object_containing(ptr)
                        if obj is not self.project.loader.main_object:
                            # the pointer does not come from current binary. skip.
                            continue

                        if self._seg_list.is_occupied(ptr):
                            sort = self._seg_list.occupied_by_sort(ptr)
                            if sort == 'code':
                                continue
                            elif sort == 'pointer-array':
                                continue
                            # TODO: other types
                        if ptr not in self._memory_data:
                            self._memory_data[ptr] = MemoryData(ptr, 0, 'unknown', None, None, None, None,
                                                                pointer_addr=data_addr + j
                                                                )
                            new_data_found = True

            else:
                memory_data.size = memory_data.max_size

            self._seg_list.occupy(data_addr, memory_data.size, memory_data.sort)

        return new_data_found

    def _guess_data_type(self, irsb, irsb_addr, stmt_idx, data_addr, max_size, content_holder=None):  # pylint: disable=unused-argument
        """
        Make a guess to the data type.

        Users can provide their own data type guessing code when initializing CFGFast instance, and each guessing
        handler will be called if this method fails to determine what the data is.

        :param pyvex.IRSB irsb: The pyvex IRSB object.
        :param int irsb_addr: Address of the IRSB.
        :param int stmt_idx: ID of the statement.
        :param int data_addr: Address of the data.
        :param int max_size: The maximum size this data entry can be.
        :return: a tuple of (data type, size). (None, None) if we fail to determine the type or the size.
        :rtype: tuple
        """

        if max_size is None:
            max_size = 0

        if self._seg_list.is_occupied(data_addr) and self._seg_list.occupied_by_sort(data_addr) == 'code':
            # it's a code reference
            # TODO: Further check if it's the beginning of an instruction
            return "code reference", 0

        pointer_size = self.project.arch.bits / 8

        # who's using it?
        if isinstance(self.project.loader.main_object, cle.MetaELF):
            plt_entry = self.project.loader.main_object.reverse_plt.get(irsb_addr, None)
            if plt_entry is not None:
                # IRSB is owned by plt!
                return "GOT PLT Entry", pointer_size

        pointers_count = 0

        max_pointer_array_size = min(512 * pointer_size, max_size)
        for i in xrange(0, max_pointer_array_size, pointer_size):
            ptr = self._fast_memory_load_pointer(data_addr + i)

            if ptr is not None:
                #if self._seg_list.is_occupied(ptr) and self._seg_list.occupied_by_sort(ptr) == 'code':
                #    # it's a code reference
                #    # TODO: Further check if it's the beginning of an instruction
                #    pass
                if self._addr_belongs_to_section(ptr) is not None or self._addr_belongs_to_segment(ptr) is not None or \
                        (self._extra_memory_regions and
                         next(((a < ptr < b) for (a, b) in self._extra_memory_regions), None)
                         ):
                    # it's a pointer of some sort
                    # TODO: Determine what sort of pointer it is
                    pointers_count += 1
                else:
                    break

        if pointers_count:
            return "pointer-array", pointer_size * pointers_count

        block, block_size = self._fast_memory_load(data_addr)

        # Is it an unicode string?
        # TODO: Support unicode string longer than the max length
        if block_size >= 4 and block[1] == 0 and block[3] == 0 and chr(block[0]) in self.PRINTABLES:
            max_unicode_string_len = 1024
            unicode_str = self._ffi.string(self._ffi.cast("wchar_t*", block), max_unicode_string_len)
            if (len(unicode_str) and  # pylint:disable=len-as-condition
                    all([ c in self.PRINTABLES for c in unicode_str])):
                if content_holder is not None:
                    content_holder.append(unicode_str)
                return "unicode", (len(unicode_str) + 1) * 2

        # Is it a null-terminated printable string?
        max_string_len = min([ block_size, max_size, 4096 ])
        s = self._ffi.string(self._ffi.cast("char*", block), max_string_len)
        if len(s):  # pylint:disable=len-as-condition
            if all([ c in self.PRINTABLES for c in s ]):
                # it's a string
                # however, it may not be terminated
                if content_holder is not None:
                    content_holder.append(s)
                return "string", min(len(s) + 1, max_string_len)

        for handler in self._data_type_guessing_handlers:
            sort, size = handler(self, irsb, irsb_addr, stmt_idx, data_addr, max_size)
            if sort is not None:
                return sort, size

        return None, None

    # Indirect jumps processing

    def _resolve_indirect_jump_timelessly(self, addr, block, func_addr, jumpkind):
        """
        Checks if MIPS32 and calls MIPS32 check, otherwise false

        :param int addr: irsb address
        :param pyvex.IRSB block: irsb
        :param int func_addr: Function address
        :return: If it was resolved and targets alongside it
        :rtype: tuple
        """

        for res in self.timeless_indirect_jump_resolvers:
            if res.filter(self, addr, func_addr, block, jumpkind):
                r, resolved_targets = res.resolve(self, addr, func_addr, block, jumpkind)
                if r:
                    return True, resolved_targets
        return False, [ ]

    def _resolve_plt(self, addr, irsb, indir_jump):
        """
        Determine if the IRSB at the given address is a PLT stub. If it is, concretely execute the basic block to
        resolve the jump target.

        :param int addr:                Address of the block.
        :param irsb:                    The basic block.
        :param IndirectJump indir_jump: The IndirectJump instance.
        :return:                        True if the IRSB represents a PLT stub and we successfully resolved the target.
                                        False otherwise.
        :rtype:                         bool
        """

        # is the address identified by CLE as a PLT stub?
        if self.project.loader.all_elf_objects:
            # restrict this heuristics to ELF files only
            if not any([ addr in obj.reverse_plt for obj in self.project.loader.all_elf_objects ]):
                return False

        # try to resolve the jump target
        simsucc = SimEngineVEX().process(self._initial_state, irsb, force_addr=addr)
        if len(simsucc.successors) == 1:
            ip = simsucc.successors[0].ip
            if ip._model_concrete is not ip:
                target_addr = ip._model_concrete.value
                if (self.project.loader.find_object_containing(target_addr) is not
                        self.project.loader.main_object) \
                        or self.project.is_hooked(target_addr):
                    # resolved!
                    # Fill the IndirectJump object
                    indir_jump.resolved_targets.add(target_addr)
                    l.debug("Address %#x is resolved as a PLT entry, jumping to %#x", addr, target_addr)
                    return True

        return False

    def _process_indirect_jumps(self):
        """
        Resolve indirect jumps found in previous scanning.

        Currently we support resolving the following types of indirect jumps:
        - Ijk_Call (disabled now): indirect calls where the function address is passed in from a proceeding basic block
        - Ijk_Boring: jump tables
        - For an up-to-date list, see analyses/cfg/indirect_jump_resolvers

        :return: a set of 4-tuples: (resolved indirect jump target, caller's func addr, caller's basic block addr, jumpkind)
        :rtype: set
        """

        all_targets = set()
        jumps_resolved = { }
        l.info("%d indirect jumps to resolve.", len(self._indirect_jumps_to_resolve))

        for jump in self._indirect_jumps_to_resolve:  # type: IndirectJump
            jumps_resolved[jump] = False

            resolved = False
            targets = None

            for resolver in self.indirect_jump_resolvers:
                resolver.base_state = self._base_state
                block = self._lift(jump.addr)

                if not resolver.filter(self, jump.addr, jump.func_addr, block, jump.jumpkind):
                    continue

                resolved, targets = resolver.resolve(self, jump.addr, jump.func_addr, block, jump.jumpkind)
                if resolved:
                    break

            if resolved:
                jumps_resolved[jump] = True
                all_targets |= set([ (t, jump.func_addr, jump.addr, jump.jumpkind) for t in targets ])

        for jump, resolved in jumps_resolved.iteritems():
            self._indirect_jumps_to_resolve.remove(jump)
            self._deregister_analysis_job(jump.func_addr, jump)

            if not resolved:
                # add a node from this node to the UnresolvableTarget node
                src_node = self._nodes[jump.addr]
                dst_node = CFGNode(self._unresolvable_target_addr, 0, self,
                                   function_address=self._unresolvable_target_addr,
                                   simprocedure_name='UnresolvableTarget',
                                   )

                # add the dst_node to self._nodes
                if self._unresolvable_target_addr not in self._nodes:
                    self._nodes[self._unresolvable_target_addr] = dst_node
                    self._nodes_by_addr[self._unresolvable_target_addr].append(dst_node)

                self._graph_add_edge(dst_node, src_node, jump.jumpkind, jump.ins_addr, jump.stmt_idx)
                # mark it as a jumpout site for that function
                self._function_add_transition_edge(self._unresolvable_target_addr, src_node, jump.func_addr,
                                                   to_outside=True,
                                                   to_function_addr=self._unresolvable_target_addr,
                                                   ins_addr=jump.ins_addr,
                                                   stmt_idx=jump.stmt_idx,
                                                   )
                # tell KnowledgeBase that it's not resolved
                # TODO: self.kb._unresolved_indirect_jumps is not processed during normalization. Fix it.
                self.kb.unresolved_indirect_jumps.add(jump.addr)

        return all_targets

    # Removers

    def _remove_redundant_overlapping_blocks(self):
        """
        On some architectures there are sometimes garbage bytes (usually nops) between functions in order to properly
        align the succeeding function. CFGFast does a linear sweeping which might create duplicated blocks for
        function epilogues where one block starts before the garbage bytes and the other starts after the garbage bytes.

        This method enumerates all blocks and remove overlapping blocks if one of them is aligned to 0x10 and the other
        contains only garbage bytes.

        :return: None
        """

        sorted_nodes = sorted(self.graph.nodes(), key=lambda n: n.addr if n is not None else 0)

        all_plt_stub_addrs = set(itertools.chain.from_iterable(obj.reverse_plt.keys() for obj in self.project.loader.all_objects if isinstance(obj, cle.MetaELF)))

        # go over the list. for each node that is the beginning of a function and is not properly aligned, if its
        # leading instruction is a single-byte or multi-byte nop, make sure there is another CFGNode starts after the
        # nop instruction

        nodes_to_append = {}
        # pylint:disable=too-many-nested-blocks
        for a in sorted_nodes:
            if a.addr in self.functions and a.addr not in all_plt_stub_addrs and \
                    not self._addr_hooked_or_syscall(a.addr):
                all_in_edges = self.graph.in_edges(a, data=True)
                if not any([data['jumpkind'] == 'Ijk_Call' for _, _, data in all_in_edges]):
                    # no one is calling it
                    # this function might be created from linear sweeping
                    try:
                        block = self._lift(a.addr, size=0x10 - (a.addr % 0x10))
                        vex_block = block.vex
                    except SimTranslationError:
                        continue

                    nop_length = None

                    if self._is_noop_block(vex_block):
                        # fast path: in most cases, the entire block is a single byte or multi-byte nop, which VEX
                        # optimizer is able to tell
                        nop_length = block.size

                    else:
                        # this is not a no-op block. Determine where nop instructions terminate.
                        insns = block.capstone.insns
                        if insns:
                            nop_length = self._get_nop_length(insns)

                    if nop_length <= 0:
                        continue

                    # leading nop for alignment.
                    next_node_addr = a.addr + nop_length
                    if nop_length < a.size and \
                            not (next_node_addr in self._nodes or next_node_addr in nodes_to_append):
                        # create a new CFGNode that starts there
                        next_node_size = a.size - nop_length
                        next_node = CFGNode(next_node_addr, next_node_size, self,
                                            function_address=next_node_addr,
                                            instruction_addrs=[i for i in a.instruction_addrs
                                                               if next_node_addr <= i
                                                                < next_node_addr + next_node_size
                                                               ],
                                            thumb=a.thumb,
                                            byte_string=None if a.byte_string is None else a.byte_string[nop_length:],
                                            )
                        # create edges accordingly
                        all_out_edges = self.graph.out_edges(a, data=True)
                        for _, dst, data in all_out_edges:
                            self.graph.add_edge(next_node, dst, **data)

                        nodes_to_append[next_node_addr] = next_node

                        # make sure there is a function begins there
                        try:
                            snippet = self._to_snippet(addr=next_node_addr, size=next_node_size,
                                                       base_state=self._base_state)
                            self.functions._add_node(next_node_addr, snippet)
                        except (SimEngineError, SimMemoryError):
                            continue

        # append all new nodes to sorted nodes
        if nodes_to_append:
            sorted_nodes = sorted(sorted_nodes + nodes_to_append.values(), key=lambda n: n.addr if n is not None else 0)

        removed_nodes = set()

        a = None  # it always hold the very recent non-removed node

        for i in xrange(len(sorted_nodes)):

            if a is None:
                a = sorted_nodes[0]
                continue

            b = sorted_nodes[i]
            if self._addr_hooked_or_syscall(b.addr):
                continue

            if b in removed_nodes:
                # skip all removed nodes
                continue

            if a.addr <= b.addr and \
                    (a.addr + a.size > b.addr):
                # They are overlapping

                try:
                    block = self.project.factory.fresh_block(a.addr, b.addr - a.addr, backup_state=self._base_state)
                except SimTranslationError:
                    a = b
                    continue
                if block.capstone.insns and all([ self._is_noop_insn(insn) for insn in block.capstone.insns ]):
                    # It's a big nop - no function starts with nop

                    # add b to indices
                    self._nodes[b.addr] = b
                    self._nodes_by_addr[b.addr].append(b)

                    # shrink a
                    self._shrink_node(a, b.addr - a.addr, remove_function=False)

                    a = b
                    continue

                all_functions = self.kb.functions

                # now things are a little harder
                # if there is no incoming edge to b, we should replace b with a
                # this is mostly because we misidentified the function beginning. In fact a is the function beginning,
                # but somehow we thought b is the beginning
                if a.addr + a.size == b.addr + b.size:
                    in_edges = len([ _ for _, _, data in self.graph.in_edges([b], data=True) ])
                    if in_edges == 0:
                        # we use node a to replace node b
                        # link all successors of b to a
                        for _, dst, data in self.graph.out_edges([b], data=True):
                            self.graph.add_edge(a, dst, **data)

                        if b.addr in self._nodes:
                            del self._nodes[b.addr]
                        if b.addr in self._nodes_by_addr and b in self._nodes_by_addr[b.addr]:
                            self._nodes_by_addr[b.addr].remove(b)

                        self.graph.remove_node(b)

                        if b.addr in all_functions:
                            del all_functions[b.addr]

                        # skip b
                        removed_nodes.add(b)

                        continue

                # next case - if b is directly from function prologue detection, or a basic block that is a successor of
                # a wrongly identified basic block, we might be totally misdecoding b
                if b.instruction_addrs[0] not in a.instruction_addrs:
                    # use a, truncate b

                    new_b_addr = a.addr + a.size  # b starts right after a terminates
                    new_b_size = b.addr + b.size - new_b_addr  # this may not be the size we want, since b might be
                                                               # misdecoded

                    # totally remove b
                    if b.addr in self._nodes:
                        del self._nodes[b.addr]
                    if b.addr in self._nodes_by_addr and b in self._nodes_by_addr[b.addr]:
                        self._nodes_by_addr[b.addr].remove(b)

                    self.graph.remove_node(b)

                    if b.addr in all_functions:
                        del all_functions[b.addr]

                    removed_nodes.add(b)

                    if new_b_size > 0:
                        # there are still some parts left in node b - we don't want to lose it
                        self._scan_block(new_b_addr, a.function_address, None, None, None, None)

                    continue

                # for other cases, we'll let them be for now

            a = b # update a

    def _remove_node(self, node):
        """
        Remove a CFGNode from self.graph as well as from the function manager (if it is the beginning of a function)

        :param CFGNode node: The CFGNode to remove from the graph.
        :return: None
        """

        self.graph.remove_node(node)
        if node.addr in self._nodes:
            del self._nodes[node.addr]

        # We wanna remove the function as well
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

        if node.addr in self.kb.functions.callgraph:
            self.kb.functions.callgraph.remove_node(node.addr)

    def _shrink_node(self, node, new_size, remove_function=True):
        """
        Shrink the size of a node in CFG.

        :param CFGNode node: The CFGNode to shrink
        :param int new_size: The new size of the basic block
        :param bool remove_function: If there is a function starting at `node`, should we remove that function or not.
        :return: None
        """

        # Generate the new node
        new_node = CFGNode(node.addr, new_size, self,
                           function_address=None if remove_function else node.function_address,
                           instruction_addrs=[i for i in node.instruction_addrs
                                              if node.addr <= i < node.addr + new_size
                                              ],
                           thumb=node.thumb,
                           byte_string=None if node.byte_string is None else node.byte_string[:new_size]
                           )

        old_in_edges = self.graph.in_edges(node, data=True)

        for src, _, data in old_in_edges:
            self.graph.add_edge(src, new_node, **data)

        successor_node_addr = node.addr + new_size
        if successor_node_addr in self._nodes:
            successor = self._nodes[successor_node_addr]
        else:
            successor_size = node.size - new_size
            successor = CFGNode(successor_node_addr, successor_size, self,
                                function_address=successor_node_addr if remove_function else node.function_address,
                                instruction_addrs=[i for i in node.instruction_addrs if i >= node.addr + new_size],
                                thumb=node.thumb,
                                byte_string=None if node.byte_string is None else node.byte_string[new_size:]
                                )
        self.graph.add_edge(new_node, successor, jumpkind='Ijk_Boring')

        # if the node B already has resolved targets, we will skip all unresolvable successors when adding old out edges
        # from node A to node B.
        # this matters in cases where node B is resolved as a special indirect jump entry (like a PLT stub), but (node
        # A + node B) wasn't properly resolved.
        has_resolved_targets = any([ node_.addr != self._unresolvable_target_addr
                                     for node_ in self.graph.successors(successor) ]
                                   )

        old_out_edges = self.graph.out_edges(node, data=True)
        for _, dst, data in old_out_edges:
            if (has_resolved_targets and dst.addr != self._unresolvable_target_addr) or \
                    not has_resolved_targets:
                self.graph.add_edge(successor, dst, **data)

        # remove the old node from indices
        if node.addr in self._nodes and self._nodes[node.addr] is node:
            del self._nodes[node.addr]
        if node.addr in self._nodes_by_addr and node in self._nodes_by_addr[node.addr]:
            self._nodes_by_addr[node.addr].remove(node)

        # remove the old node form the graph
        self.graph.remove_node(node)

        # add the new node to indices
        self._nodes[new_node.addr] = new_node
        self._nodes_by_addr[new_node.addr].append(new_node)

        # the function starting at this point is probably totally incorrect
        # hopefull future call to `make_functions()` will correct everything
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

            if not remove_function:
                # add functions back
                self._function_add_node(node.addr, node.addr)
                successor_node = self.get_any_node(successor_node_addr)
                if successor_node and successor_node.function_address == node.addr:
                    # if there is absolutely no predecessors to successor_node, we'd like to add it as a new function
                    # so that it will not be left behind
                    if not list(self.graph.predecessors(successor_node)):
                        self._function_add_node(successor_node_addr, successor_node_addr)

        #if node.addr in self.kb.functions.callgraph:
        #    self.kb.functions.callgraph.remove_node(node.addr)

    def _analyze_all_function_features(self):
        """
        Iteratively analyze all changed functions, update their returning attribute, until a fix-point is reached (i.e.
        no new returning/not-returning functions are found).

        :return: None
        """

        while True:
            new_changes = self._iteratively_analyze_function_features()
            new_returning_functions = new_changes['functions_do_not_return']
            new_not_returning_functions = new_changes['functions_return']

            if not new_returning_functions and not new_not_returning_functions:
                break

            for returning_function in new_returning_functions:
                if returning_function.addr in self._function_returns:
                    for fr in self._function_returns[returning_function.addr]:
                        # Confirm them all
                        self._changed_functions.add(fr.caller_func_addr)


                        return_to_node = self._nodes.get(fr.return_to, None)
                        if return_to_node is None:
                            return_to_snippet = self._to_snippet(addr=fr.return_to, base_state=self._base_state)
                        else:
                            return_to_snippet = self._to_snippet(cfg_node=self._nodes[fr.return_to])

                        self.kb.functions._add_return_from_call(fr.caller_func_addr, fr.callee_func_addr,
                                                                return_to_snippet)

                    del self._function_returns[returning_function.addr]

            for not_returning_function in new_not_returning_functions:
                if not_returning_function.addr in self._function_returns:
                    for fr in self._function_returns[not_returning_function.addr]:
                        # Remove all those FakeRet edges
                        self._changed_functions.add(fr.caller_func_addr)

                        # convert them to codenodes
                        try:
                            call_site_node = self._to_snippet(self._nodes[fr.call_site_addr])
                        except KeyError:
                            call_site_node = fr.call_site_addr

                        # We always use the address instead of the block here, because the first time this fake ret is
                        # added into the function, we might be using the address, and in that case, the size of the
                        # block in function.blocks is unknown to us.
                        return_to = fr.return_to
                        if type(return_to) in (int, long):
                            return_to = self._to_snippet(addr=return_to, base_state=self._base_state)

                        self.kb.functions._remove_fakeret(fr.caller_func_addr, call_site_node, return_to)

                    del self._function_returns[not_returning_function.addr]

    def _clean_pending_exits(self):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning syscalls
        b) they are the return exits of non-returning functions

        :return: None
        """

        pending_exits_to_remove = []

        for i, pe in enumerate(self._pending_jobs):

            if pe.returning_source is None:
                # The original call failed. This pending exit must be followed.
                continue

            func = self.kb.functions.function(pe.returning_source)
            if func is None:
                # Why does it happen?
                l.warning("An expected function at %s is not found. Please report it to Fish.",
                          hex(pe.returning_source) if pe.returning_source is not None else 'None')
                continue

            if func.returning is False:
                # Oops, it's not returning
                # Remove this pending exit
                pending_exits_to_remove.append(i)

        for index in reversed(pending_exits_to_remove):
            job = self._pending_jobs[index]
            self._deregister_analysis_job(job.func_addr, job)
            del self._pending_jobs[index]

    #
    # Graph utils
    #

    def _graph_add_edge(self, cfg_node, src_node, src_jumpkind, src_ins_addr, src_stmt_idx):
        """
        Add edge between nodes, or add node if entry point

        :param CFGNode cfg_node: node which is jumped to
        :param CFGNode src_node: node which is jumped from none if entry point
        :param str src_jumpkind: what type of jump the edge takes
        :param int or str src_stmt_idx: source statements ID
        :return: None
        """

        if src_node is None:
            self.graph.add_node(cfg_node)
        else:
            self.graph.add_edge(src_node, cfg_node, jumpkind=src_jumpkind, ins_addr=src_ins_addr,
                                stmt_idx=src_stmt_idx)

    @staticmethod
    def _get_return_endpoints(func):
        all_endpoints = func.endpoints_with_type
        return all_endpoints.get('return', [ ])

    def _get_jumpout_targets(self, func):
        jumpout_targets = set()
        callgraph_outedges = self.functions.callgraph.out_edges(func.addr, data=True)
        # find the ones whose type is transition
        for _, dst, data in callgraph_outedges:
            if data.get('type', None) == 'transition':
                jumpout_targets.add(dst)
        return jumpout_targets

    def _get_return_sources(self, func):

        # We will create a return edge for each returning point of this function

        # Get all endpoints
        all_endpoints = func.endpoints_with_type
        # However, we do not want to create return edge if the endpoint is not a returning endpoint.
        # For example, a PLT stub on x86/x64 always jump to the real library function, so we should create a return
        # edge from that library function to the call site, instead of creating a return edge from the PLT stub to
        # the call site.
        if all_endpoints['transition']:
            # it has jump outs
            # it is, for example, a PLT stub
            # we take the endpoints of the function it calls. this is not always correct, but it can handle many
            # cases.
            jumpout_targets = self._get_jumpout_targets(func)
            jumpout_target_endpoints = set()

            for jumpout_func_addr in jumpout_targets:
                if jumpout_func_addr in self.functions:
                    jumpout_target_endpoints |= set(self._get_return_endpoints(self.functions[jumpout_func_addr]))

            endpoints = jumpout_target_endpoints
        else:
            endpoints = set()

        # then we take all return endpoints of the current function
        endpoints |= all_endpoints.get('return', set())

        return endpoints

    def _make_return_edges(self):
        """
        For each returning function, create return edges in self.graph.

        :return: None
        """

        for func_addr, func in self.functions.iteritems():
            if func.returning is False:
                continue

            # get the node on CFG
            if func.startpoint is None:
                l.warning('Function %#x does not have a startpoint (yet).', func_addr)
                continue

            startpoint = self.get_any_node(func.startpoint.addr)
            if startpoint is None:
                # weird...
                l.warning('No CFGNode is found for function %#x in _make_return_edges().', func_addr)
                continue

            endpoints = self._get_return_sources(func)

            # get all callers
            callers = self.get_predecessors(startpoint, jumpkind='Ijk_Call')
            # for each caller, since they all end with a call instruction, get the immediate successor
            return_targets = itertools.chain.from_iterable(
                self.get_successors(caller, excluding_fakeret=False, jumpkind='Ijk_FakeRet') for caller in callers
            )
            return_targets = set(return_targets)

            for ep in endpoints:
                src = self.get_any_node(ep.addr)
                for rt in return_targets:
                    if not src.instruction_addrs:
                        ins_addr = None
                    else:
                        if self.project.arch.branch_delay_slot:
                            if len(src.instruction_addrs) > 1:
                                ins_addr = src.instruction_addrs[-2]
                            else:
                                l.error('At %s: expecting more than one instruction. Only got one.', src)
                                ins_addr = None
                        else:
                            ins_addr = src.instruction_addrs[-1]

                    self._graph_add_edge(rt, src, 'Ijk_Ret', ins_addr, 'default')

    #
    # Function utils
    #

    def _function_add_node(self, addr, function_addr):
        """
        Adds node to function manager, converting address to CodeNode if
        possible

        :param int addr: node address
        :param int function_addr: address of function
        :return: None
        """
        node = self._nodes.get(addr, None)
        if node is None:
            snippet = self._to_snippet(addr=addr, base_state=self._base_state)
        else:
            snippet = self._to_snippet(cfg_node=self._nodes[addr])
        self.kb.functions._add_node(function_addr, snippet)

    def _function_add_transition_edge(self, addr, src_node, function_addr, to_outside=False, to_function_addr=None,
                                      stmt_idx=None, ins_addr=None):
        """
        Add a transition edge to the function transiton map.

        :param int addr: Address that the control flow transits to.
        :param CFGNode src_node: The source node that the control flow transits from.
        :param int function_addr: Function address.
        :return: True if the edge is correctly added. False if any exception occurred (for example, the target address
                 does not exist)
        :rtype: bool
        """

        try:
            target_node = self._nodes.get(addr, None)
            if target_node is None:
                target_snippet = self._to_snippet(addr=addr, base_state=self._base_state)
            else:
                target_snippet = self._to_snippet(cfg_node=target_node)

            if src_node is None:
                # Add this basic block into the function manager
                self.kb.functions._add_node(function_addr, target_snippet)
            else:
                src_snippet = self._to_snippet(cfg_node=src_node)
                if not to_outside:
                    self.kb.functions._add_transition_to(function_addr, src_snippet, target_snippet, stmt_idx=stmt_idx,
                                                         ins_addr=ins_addr
                                                         )
                else:
                    self.kb.functions._add_outside_transition_to(function_addr, src_snippet, target_snippet,
                                                                 to_function_addr=to_function_addr,
                                                                 stmt_idx=stmt_idx, ins_addr=ins_addr
                                                                 )
            return True
        except (SimMemoryError, SimEngineError):
            return False

    def _function_add_call_edge(self, addr, src_node, ret_addr, function_addr, syscall=False, stmt_idx=None,
                                ins_addr=None
                                ):
        """
        Add a call edge to the function transition map.

        :param int addr: Address that is being called (callee).
        :param CFGNode src_node: The source CFG node (caller).
        :param int ret_addr: Address that returns to (in case the function returns).
        :param int function_addr: Function address..
        :param bool syscall: If this is a call to a syscall or not.
        :param int or str stmt_idx: Statement ID of this call.
        :param int or None ins_addr: Instruction address of this call.
        :return: True if the edge is added. False if any exception occurred.
        :rtype: bool
        """
        try:
            if src_node is None:
                self.kb.functions._add_node(function_addr, addr, syscall=syscall)
            else:
                src_snippet = self._to_snippet(cfg_node=src_node)

                return_to_outside = False

                if ret_addr is None:
                    ret_snippet = None
                else:
                    dst_node = self._nodes.get(ret_addr, None)
                    if dst_node is None:
                        ret_snippet = self._to_snippet(addr=ret_addr, base_state=self._base_state)
                    else:
                        ret_snippet = self._to_snippet(cfg_node=dst_node)
                        return_to_outside = dst_node.function_address != function_addr

                self.kb.functions._add_call_to(function_addr, src_snippet, addr, ret_snippet, syscall=syscall,
                                               stmt_idx=stmt_idx, ins_addr=ins_addr,
                                               return_to_outside=return_to_outside,
                                               )
            return True
        except (SimMemoryError, SimEngineError):
            return False

    def _function_add_fakeret_edge(self, addr, src_node, function_addr, confirmed=None):
        """
        Generate CodeNodes for target and source, if no source node add node
        for function, otherwise creates fake return to in function manager

        :param int addr: target address
        :param angr.analyses.CFGNode src_node: source node
        :param int function_addr: address of function
        :param confirmed: used as attribute on eventual digraph
        :return: None
        """

        target_node = self._nodes.get(addr, None)
        if target_node is None:
            target_snippet = self._to_snippet(addr=addr, base_state=self._base_state)
        else:
            target_snippet = self._to_snippet(cfg_node=target_node)

        if src_node is None:
            self.kb.functions._add_node(function_addr, target_snippet)
        else:
            src_snippet = self._to_snippet(cfg_node=src_node)
            self.kb.functions._add_fakeret_to(function_addr, src_snippet, target_snippet, confirmed=confirmed)

    def _function_add_return_site(self, addr, function_addr):
        """
        Generate CodeNodes for target address, registers node for function to
        function manager as return site

        :param int addr: target address
        :param int function_addr: address of function
        :return: None
        """
        try:
            target = self._to_snippet(self._nodes[addr])
        except KeyError:
            target = addr

        self.kb.functions._add_return_from(function_addr, target)

    def _function_add_return_edge(self, return_from_addr, return_to_addr, function_addr):
        """
        Generate CodeNodes for return_to_addr, add this node for function to
        function manager generating new edge

        :param int return_from_addr: target address
        :param int return_to_addr: target address
        :param int function_addr: address of function
        :return: None
        """

        return_to_node = self._nodes.get(return_to_addr, None)
        if return_to_node is None:
            return_to_snippet = self._to_snippet(addr=return_to_addr, base_state=self._base_state)
            to_outside = False
        else:
            return_to_snippet = self._to_snippet(cfg_node=return_to_node)
            to_outside = return_to_node.function_address != function_addr

        self.kb.functions._add_return_from_call(function_addr, return_from_addr, return_to_snippet,
                                                to_outside=to_outside)

    #
    # Architecture-specific methods
    #

    def _arm_track_lr_on_stack(self, addr, irsb, function):
        """
        At the beginning of the basic block, we check if the first instruction stores the LR register onto the stack.
        If it does, we calculate the offset of that store, and record the offset in function.info.

        For instance, here is the disassembly of a THUMB mode function:

        000007E4  STR.W           LR, [SP,#var_4]!
        000007E8  MOV             R2, R1
        000007EA  SUB             SP, SP, #0xC
        000007EC  MOVS            R1, #0
        ...
        00000800  ADD             SP, SP, #0xC
        00000802  LDR.W           PC, [SP+4+var_4],#4

        The very last basic block has a jumpkind of Ijk_Boring, which is because VEX cannot do such complicated analysis
        to determine the real jumpkind.

        As we can see, instruction 7e4h stores LR at [sp-4], and at the end of this function, instruction 802 loads LR
        from [sp], then increments sp by 4. We execute the first instruction, and track the following things:
        - if the value from register LR is stored onto the stack.
        - the difference between the offset of the LR store on stack, and the SP after the store.

        If at the end of the function, the LR is read out from the stack at the exact same stack offset, we will change
        the jumpkind of the final IRSB to Ijk_Ret.

        This method can be enabled by setting "ret_jumpkind_heuristics", which is an architecture-specific option on
        ARM, to True.

        :param int addr: Address of the basic block.
        :param pyvex.IRSB irsb: The basic block object.
        :param Function function: The function instance.
        :return: None
        """

        if 'lr_saved_on_stack' in function.info:
            return

        #
        # if it does, we log it down to the Function object.
        lr_offset = self.project.arch.registers['lr'][0]
        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7fff0000
        initial_lr = 0xabcdef
        tmps = {}

        # pylint:disable=too-many-nested-blocks
        for stmt in irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.IMark):
                if stmt.addr + stmt.delta != addr:
                    break
            elif isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = stmt.data
                if isinstance(data, pyvex.IRExpr.Get):
                    if data.offset == sp_offset:
                        tmps[stmt.tmp] = initial_sp
                    elif data.offset == lr_offset:
                        tmps[stmt.tmp] = initial_lr
                elif isinstance(data, pyvex.IRExpr.Binop):
                    if data.op == 'Iop_Sub32':
                        arg0, arg1 = data.args
                        if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
                            if arg0.tmp in tmps:
                                tmps[stmt.tmp] = tmps[arg0.tmp] - arg1.con.value

            elif isinstance(stmt, (pyvex.IRStmt.Store, pyvex.IRStmt.StoreG)):
                data = stmt.data
                storing_lr = False
                if isinstance(data, pyvex.IRExpr.RdTmp):
                    if data.tmp in tmps:
                        val = tmps[data.tmp]
                        if val == initial_lr:
                            # we are storing LR to somewhere
                            storing_lr = True
                if storing_lr:
                    if isinstance(stmt.addr, pyvex.IRExpr.RdTmp):
                        if stmt.addr.tmp in tmps:
                            storing_addr = tmps[stmt.addr.tmp]

                            function.info['lr_saved_on_stack'] = True
                            function.info['lr_on_stack_offset'] = storing_addr - initial_sp
                            break

        if 'lr_saved_on_stack' not in function.info:
            function.info['lr_saved_on_stack'] = False

    def _arm_track_read_lr_from_stack(self, addr, irsb, function):  # pylint:disable=unused-argument
        """
        At the end of a basic block, simulate the very last instruction to see if the return address is read from the
        stack and written in PC. If so, the jumpkind of this IRSB will be set to Ijk_Ret. For detailed explanations,
        please see the documentation of _arm_track_lr_on_stack().

        :param int addr: The address of the basic block.
        :param pyvex.IRSB irsb: The basic block object.
        :param Function function: The function instance.
        :return: None
        """

        if 'lr_saved_on_stack' not in function.info or not function.info['lr_saved_on_stack']:
            return

        sp_offset = self.project.arch.sp_offset
        initial_sp = 0x7fff0000
        last_sp = None
        tmps = {}
        last_imark = next((stmt for stmt in reversed(irsb.statements)
                           if isinstance(stmt, pyvex.IRStmt.IMark)
                           ), 0
                          )
        tmp_irsb = self._lift(last_imark.addr + last_imark.delta).vex
        # pylint:disable=too-many-nested-blocks
        for stmt in tmp_irsb.statements:
            if isinstance(stmt, pyvex.IRStmt.WrTmp):
                data = stmt.data
                if isinstance(data, pyvex.IRExpr.Get) and data.offset == sp_offset:
                    # t0 = GET:I32(sp)
                    tmps[stmt.tmp] = initial_sp
                elif isinstance(data, pyvex.IRExpr.Binop):
                    # only support Add
                    if data.op == 'Iop_Add32':
                        arg0, arg1 = data.args
                        if isinstance(arg0, pyvex.IRExpr.RdTmp) and isinstance(arg1, pyvex.IRExpr.Const):
                            if arg0.tmp in tmps:
                                tmps[stmt.tmp] = tmps[arg0.tmp] + arg1.con.value
                elif isinstance(data, pyvex.IRExpr.Load):
                    if isinstance(data.addr, pyvex.IRExpr.RdTmp):
                        if data.addr.tmp in tmps:
                            tmps[stmt.tmp] = ('load', tmps[data.addr.tmp])
            elif isinstance(stmt, pyvex.IRStmt.Put):
                if stmt.offset == sp_offset and isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    if stmt.data.tmp in tmps:
                        # loading things into sp
                        last_sp = tmps[stmt.data.tmp]

        if last_sp is not None and isinstance(tmp_irsb.next, pyvex.IRExpr.RdTmp):
            val = tmps[tmp_irsb.next.tmp]
            if isinstance(val, tuple) and val[0] == 'load':
                # the value comes from memory
                memory_addr = val[1]
                lr_on_stack_offset = memory_addr - last_sp

                if lr_on_stack_offset == function.info['lr_on_stack_offset']:
                    # the jumpkind should be Ret instead of boring
                    irsb.jumpkind = 'Ijk_Ret'

    #
    # Other methods
    #

    def _generate_cfgnode(self, addr, current_function_addr):
        """
        Generate a CFGNode that starts at `addr`.

        Since lifting machine code to IRSBs is slow, self._nodes is used as a cache of CFGNodes.

        If the current architecture is ARM, this method will try to lift the block in the mode specified by the address
        (determined by the parity of the address: even for ARM, odd for THUMB), and in case of decoding failures, try
        the other mode. If the basic block is successfully decoded in the other mode (different from the initial one),
         `addr` and `current_function_addr` are updated.

        :param int addr: Address of the basic block.
        :param int current_function_addr: Address of the current function.
        :return: A 4-tuple of (new address, new function address, CFGNode instance, IRSB object)
        :rtype: tuple
        """

        try:

            if addr in self._nodes:
                cfg_node = self._nodes[addr]
                irsb = cfg_node.irsb

                if cfg_node.function_address != current_function_addr:
                    # the node has been assigned to another function before.
                    # we should update the function address.
                    current_function_addr = cfg_node.function_address

                return addr, current_function_addr, cfg_node, irsb

            is_arm_arch = True if self.project.arch.name in ('ARMHF', 'ARMEL') else False

            if is_arm_arch:
                real_addr = addr&(~1)
            else:
                real_addr = addr

            # if possible, check the distance between `addr` and the end of this section
            distance = None
            obj = self.project.loader.find_object_containing(addr)
            if obj:
                # is there a section?
                has_executable_section = len([ sec for sec in obj.sections if sec.is_executable ]) > 0  # pylint:disable=len-as-condition
                section = self._addr_belongs_to_section(addr)
                if has_executable_section and section is None:
                    # the basic block should not exist here...
                    return None, None, None, None
                if section is not None:
                    if not section.is_executable:
                        # the section is not executable...
                        return None, None, None, None
                    distance = section.vaddr + section.memsize - real_addr
                    distance = min(distance, VEX_IRSB_MAX_SIZE)
                # TODO: handle segment information as well

            # also check the distance between `addr` and the closest function.
            # we don't want to have a basic block that spans across function boundaries
            next_func = self.functions.ceiling_func(addr)
            if next_func is not None:
                distance_to_func = next_func.addr&(-1) if is_arm_arch else next_func.addr - real_addr
                if distance_to_func != 0:
                    if distance is None:
                        distance = distance_to_func
                    else:
                        distance = min(distance, distance_to_func)

            # Let's try to create the pyvex IRSB directly, since it's much faster
            nodecode = False
            irsb = None
            irsb_string = None
            try:
                lifted_block = self._lift(addr, size=distance)
                irsb = lifted_block.vex
                irsb_string = lifted_block.bytes[:irsb.size]
            except SimTranslationError:
                nodecode = True

            if (nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode') and \
                    is_arm_arch and \
                    self._arch_options.switch_mode_on_nodecode:
                # maybe the current mode is wrong?
                nodecode = False

                if real_addr in self._nodes:
                    # it has been analyzed before
                    cfg_node = self._nodes[real_addr]
                    irsb = cfg_node.irsb
                    return real_addr, cfg_node.function_address, cfg_node, irsb

                try:
                    lifted_block = self._lift(real_addr, size=distance)
                    irsb = lifted_block.vex
                    irsb_string = lifted_block.bytes[:irsb.size]
                except SimTranslationError:
                    nodecode = True

                if not (nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode'):
                    # it is decodeable
                    if current_function_addr == addr:
                        current_function_addr = real_addr
                    addr = real_addr

            if nodecode or irsb.size == 0 or irsb.jumpkind == 'Ijk_NoDecode':
                # decoding error
                # we still occupy that location since it cannot be decoded anyways
                if irsb is None:
                    irsb_size = 1
                else:
                    irsb_size = irsb.size if irsb.size > 0 else 1
                self._seg_list.occupy(addr, irsb_size, 'nodecode')
                return None, None, None, None

            is_thumb = False
            # Occupy the block in segment list
            if irsb.size > 0:
                if is_arm_arch and addr % 2 == 1:
                    # thumb mode
                    is_thumb=True
                self._seg_list.occupy(real_addr, irsb.size, "code")

            # Create a CFG node, and add it to the graph
            cfg_node = CFGNode(addr, irsb.size, self, function_address=current_function_addr, block_id=addr,
                               irsb=irsb, thumb=is_thumb, byte_string=irsb_string,
                               )

            self._nodes[addr] = cfg_node
            self._nodes_by_addr[addr].append(cfg_node)

            return addr, current_function_addr, cfg_node, irsb

        except (SimMemoryError, SimEngineError):
            return None, None, None, None

    def _process_block_arch_specific(self, addr, irsb, func_addr):  # pylint: disable=unused-argument
        """
        According to arch types ['ARMEL', 'ARMHF', 'MIPS32'] does different
        fixes

        For ARM deals with link register on the stack
        (see _arm_track_lr_on_stack)
        For MIPS32 simulates a new state where the global pointer is 0xffffffff
        from current address after three steps if the first successor does not
        adjust this value updates this function address (in function manager)
        to use a conrete global pointer

        :param int addr: irsb address
        :param pyvex.IRSB irsb: irsb
        :param func_addr: function address
        :return: None
        """
        if self.project.arch.name in ('ARMEL', 'ARMHF'):
            if self._arch_options.ret_jumpkind_heuristics:
                if addr == func_addr:
                    self._arm_track_lr_on_stack(addr, irsb, self.functions[func_addr])

                elif 'lr_saved_on_stack' in self.functions[func_addr].info and \
                        self.functions[func_addr].info['lr_saved_on_stack'] and \
                        irsb.jumpkind == 'Ijk_Boring' and \
                        irsb.next is not None and \
                        isinstance(irsb.next, pyvex.IRExpr.RdTmp):
                    # do a bunch of checks to avoid unnecessary simulation from happening
                    self._arm_track_read_lr_from_stack(addr, irsb, self.functions[func_addr])

        elif self.project.arch.name == "MIPS32":
            function = self.kb.functions.function(func_addr)
            if addr >= func_addr and addr - func_addr < 15 * 4 and 'gp' not in function.info:
                # check if gp is being written to
                last_gp_setting_insn_id = None
                insn_ctr = 0
                for stmt in irsb.statements:
                    if isinstance(stmt, pyvex.IRStmt.IMark):
                        insn_ctr += 1
                        if insn_ctr >= 10:
                            break
                    elif isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == self.project.arch.registers['gp'][0]:
                        last_gp_setting_insn_id = insn_ctr
                        break

                if last_gp_setting_insn_id is None:
                    return

                # Prudently search for $gp values
                state = self.project.factory.blank_state(addr=addr, mode="fastpath",
                                                         remove_options={o.OPTIMIZE_IR}
                                                         )
                state.regs.t9 = func_addr
                state.regs.gp = 0xffffffff
                succ = self.project.factory.successors(state, num_inst=last_gp_setting_insn_id + 1)

                if not succ.flat_successors:
                    return

                state = succ.flat_successors[0]
                if not state.regs.gp.symbolic and state.se.is_false(state.regs.gp == 0xffffffff):
                    function.info['gp'] = state.regs.gp._model_concrete.value

    #
    # Public methods
    #

    def copy(self):
        n = CFGFast.__new__(CFGFast)
        super(CFGFast, self).make_copy(n)

        n._binary = self._binary
        n._regions = self._regions
        n._pickle_intermediate_results = self._pickle_intermediate_results
        n._indirect_jump_target_limit = self._indirect_jump_target_limit
        n._collect_data_ref = self._collect_data_ref
        n._use_symbols = self._use_symbols
        n._use_function_prologues = self._use_function_prologues
        n._resolve_indirect_jumps = self._resolve_indirect_jumps
        n._force_segment = self._force_segment
        n._force_complete_scan = self._force_complete_scan

        n._progress_callback = self._progress_callback
        n._show_progressbar = self._show_progressbar

        n._exec_mem_regions = self._exec_mem_regions[::]
        n._exec_mem_region_size = self._exec_mem_region_size

        n._memory_data = self._memory_data.copy()

        n._seg_list = self._seg_list.copy()

        n._function_addresses_from_symbols = self._function_addresses_from_symbols.copy()

        n._graph = self._graph

        return n

    def output(self):
        s = "%s" % self._graph.edges(data=True)

        return s

    def generate_code_cover(self):
        """
        Generate a list of all recovered basic blocks.
        """

        lst = []
        for cfg_node in self.graph.nodes():
            size = cfg_node.size
            lst.append((cfg_node.addr, size))

        lst = sorted(lst, key=lambda x: x[0])
        return lst

register_analysis(CFGFast, 'CFGFast')
