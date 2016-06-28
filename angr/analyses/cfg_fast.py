import logging
import string
import math
import re
import struct
from collections import defaultdict

import cffi

import claripy
import simuvex
import pyvex

from ..blade import Blade
from ..analysis import register_analysis
from ..surveyors import Slicecutor
from ..annocfg import AnnotatedCFG
from ..errors import AngrTranslationError, AngrMemoryError, AngrCFGError
from .cfg_node import CFGNode
from .cfg_base import CFGBase, IndirectJump
from .forward_analysis import ForwardAnalysis
from .cfg_arch_options import CFGArchOptions

l = logging.getLogger("angr.analyses.cfg_fast")

class Segment(object):
    """
    Representing a memory block. This is not the "Segment" in ELF memory model
    """

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
        return self.end - self.start

    def copy(self):
        return Segment(self.start, self.end, self.sort)

class SegmentList(object):
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

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
                self._list = self._list[ : previous_segment_pos] + \
                            [ Segment(new_start, new_end, segment.sort) ] + \
                            self._list[ segment_pos + 1: ]
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
                        new_segments.append(Segment(segment.start, segment.end, sort))
                        if segment.start + segment.size < previous_segment.end:
                            new_segments.append(Segment(segment.end, previous_segment.end, previous_segment.sort))
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
        s = "["
        lst = []
        for segment in self._list:
            lst.append(repr(segment))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
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

    def has_blocks(self):
        """
        Returns if this segment list has any block or not. !is_empty

        :return: True if it's not empty, False otherwise
        """

        return len(self._list) > 0

    def next_free_pos(self, address):
        """
        Returns the next free position with respect to an address, excluding that address itself

        :param address: The address to begin the search with (excluding itself)
        :return: The next free position
        """

        idx = self._search(address + 1)
        if idx < len(self._list) and self._list[idx].start <= address < self._list[idx].end:
            # Occupied
            i = idx
            while i + 1 < len(self._list) and self._list[i].end == self._list[i + 1].start:
                i += 1
            if i == len(self._list):
                return self._list[-1].end
            else:
                return self._list[i].end
        else:
            return address + 1

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
        if len(self._list) == 0:
            self._list.append(Segment(address, address + size, sort))
            self._bytes_occupied += size
            return
        # Find adjacent element in our list
        idx = self._search(address)
        # print idx

        self._insert_and_merge(address, size, sort, idx)

        # self._debug_check()

    def copy(self):
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


class FunctionReturn(object):
    def __init__(self, callee_func_addr, caller_func_addr, call_site_addr, return_to):
        self.callee_func_addr = callee_func_addr
        self.caller_func_addr = caller_func_addr
        self.call_site_addr = call_site_addr
        self.return_to = return_to

    def __eq__(self, o):
        """
        Comparison

        :param FunctionReturn o: The other object
        :return: True if equal, False otherwise
        """
        return self.callee_func_addr == o.callee_func_addr and \
                self.caller_func_addr == o.caller_func_addr and \
                self.call_site_addr == o.call_site_addr and \
                self.return_to == o.return_to

    def __hash__(self):
        return hash((self.callee_func_addr, self.caller_func_addr, self.call_site_addr, self.return_to))


class MemoryData(object):
    def __init__(self, address, size, sort, irsb, irsb_addr, stmt_idx, max_size=None):
        self.address = address
        self.size = size
        self.sort = sort
        self.irsb = irsb
        self.irsb_addr = irsb_addr
        self.stmt_idx = stmt_idx

        self.max_size = max_size

        self.refs = [ ]

    def __repr__(self):
        return "\\%#x, %d bytes, %s/" % (self.address, self.size, self.sort)


class MemoryDataReference(object):
    def __init__(self, ref_ins_addr):
        self.ref_ins_addr = ref_ins_addr


class CFGEntry(object):
    """
    Defines an entry to resume the CFG recovery
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
        return "<CFGEntry%s %#08x @ func %#08x>" % (" syscall" if self.syscall else "", self.addr, self.func_addr)

    def __eq__(self, other):
        return self.addr == other.addr and \
                self.func_addr == other.func_addr and \
                self.jumpkind == other.jumpkind and \
                self.ret_target == other.ret_target and \
                self.last_addr == other.last_addr and \
                self.src_node == other.src_node and \
                self.src_stmt_idx == other.src_stmt_idx and \
                self.returning_source == other.returning_source and \
                self.syscall == other.syscall

    def __hash__(self):
        return hash((self.addr, self.func_addr, self.jumpkind, self.ret_target, self.last_addr, self.src_node,
                     self.src_stmt_idx, self.returning_source, self.syscall)
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

    def __init__(self,
                 binary=None,
                 start=None,
                 end=None,
                 pickle_intermediate_results=False,
                 symbols=True,
                 function_prologues=True,
                 resolve_indirect_jumps=True,
                 force_segment=False,
                 force_complete_scan=True,
                 indirect_jump_target_limit=100000,
                 collect_data_references=False,
                 normalize=False,
                 function_starts=None,
                 arch_options=None,
                 **extra_arch_options
                 ):
        """
        :param binary:                  The binary to recover CFG on. By default the main binary is used.
        :param int start:               The beginning address of CFG recovery.
        :param int end:                 The end address of CFG recovery.
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
        :param bool normalize:          Normalize the CFG as well as all function graphs after CFG recovery.
        :param list function_starts:    A list of extra function starting points. CFGFast will try to resume scanning
                                        from each address in the list.
        :param CFGArchOptions arch_options: Architecture-specific options.
        :param dict extra_arch_options: Any key-value pair in kwargs will be seen as an arch-specific option and will
                                        be used to set the option value in self._arch_options.

        Extra parameters that angr.Analysis takes:

        :param progress_callback:       Specify a callback function to get the progress during CFG recovery.
        :param bool show_progressbar:   Should CFGFast show a progressbar during CFG recovery or not.
        :return: None
        """

        ForwardAnalysis.__init__(self, allow_merging=False)
        CFGBase.__init__(self, 0, normalize=normalize, binary=binary, force_segment=force_segment)

        self._start = start if start is not None else (self._binary.rebase_addr + self._binary.get_min_addr())
        self._end = end if end is not None else (self._binary.rebase_addr + self._binary.get_max_addr())

        self._pickle_intermediate_results = pickle_intermediate_results
        self._indirect_jump_target_limit = indirect_jump_target_limit
        self._collect_data_ref = collect_data_references

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self._force_complete_scan = force_complete_scan

        self._extra_function_starts = function_starts

        self._arch_options = arch_options if arch_options is not None else CFGArchOptions(self.project.arch,
                                                                                          **extra_arch_options
                                                                                          )

        l.debug("Starts at %#x and ends at %#x.", self._start, self._end)

        # A mapping between (address, size) and the actual data in memory
        self._memory_data = { }

        self._initial_state = None
        self._next_addr = self._start - 1

        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

        self._indirect_jumps_to_resolve = set()

        self._jump_tables = { }

        self._function_addresses_from_symbols = self._func_addrs_from_symbols()

        self._function_prologue_addrs = None

        #
        # Variables used during analysis
        #
        self._pending_entries = None
        self._traced_addresses = None
        self._function_returns = None
        self._function_exits = None

        self._graph = None

        self._ffi = cffi.FFI()

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
    def functions(self):
        return self.kb.functions

    @property
    def memory_data(self):
        return self._memory_data

    #
    # Private methods
    #

    def __setstate__(self, s):
        self._graph = s['graph']
        self.indirect_jumps = s['indirect_jumps']

    def __getstate__(self):
        s = {
            "graph": self.graph,
            "indirect_jumps": self.indirect_jumps,
        }
        return s

    # Methods for scanning the entire image

    def _next_unscanned_addr(self, alignment=None):
        """
        Find the next address that we haven't processed

        :param alignment: Assures the address returns must be aligned by this number
        :return: An address to process next, or None if all addresses have been processed
        """

        # TODO: Take care of those functions that are already generated
        curr_addr = self._next_addr
        if self._seg_list.has_blocks:
            curr_addr = self._seg_list.next_free_pos(curr_addr)

        if alignment is not None:
            if curr_addr % alignment > 0:
                curr_addr = curr_addr - curr_addr % alignment + alignment

        # Make sure curr_addr exists in binary
        accepted = False
        for start, end in self._exec_mem_regions:
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
        if self._end is None or curr_addr < self._end:
            l.debug("Returning new recon address: 0x%08x", curr_addr)
            return curr_addr
        else:
            l.debug("0x%08x is beyond the ending point.", curr_addr)
            return None

    def _next_code_addr(self):
        """
        Call _next_unscanned_addr() first to get the next address that is not scanned. Then check if data locates at
        that address seems to be code or not. If not, we'll continue to for the next un-scanned address.
        """

        next_addr = self._next_unscanned_addr()
        if next_addr is None:
            return None

        start_addr = next_addr
        sz = ""
        is_sz = True
        while is_sz:
            # Get data until we meet a 0
            while next_addr in self._initial_state.memory:
                try:
                    l.debug("Searching address %x", next_addr)
                    val = self._initial_state.mem_concrete(next_addr, 1)
                    if val == 0:
                        if len(sz) < 4:
                            is_sz = False
                        # else:
                        #   we reach the end of the memory region
                        break
                    if chr(val) not in string.printable:
                        is_sz = False
                        break
                    sz += chr(val)
                    next_addr += 1
                except simuvex.SimValueError:
                    # Not concretizable
                    l.debug("Address 0x%08x is not concretizable!", next_addr)
                    break

            if len(sz) > 0 and is_sz:
                l.debug("Got a string of %d chars: [%s]", len(sz), sz)
                # l.debug("Occpuy %x - %x", start_addr, start_addr + len(sz) + 1)
                self._seg_list.occupy(start_addr, len(sz) + 1, "string")
                sz = ""
                next_addr = self._next_unscanned_addr()
                if next_addr is None:
                    return None
                # l.debug("next addr = %x", next_addr)
                start_addr = next_addr

            if is_sz:
                next_addr += 1

        instr_alignment = self._initial_state.arch.instruction_alignment
        if start_addr % instr_alignment > 0:
            start_addr = start_addr - start_addr % instr_alignment + \
                         instr_alignment

        return start_addr

    # Overriden methods from ForwardAnalysis

    def _entry_key(self, entry):
        return entry.addr

    def _pre_analysis(self):
        # Initialize variables used during analysis
        self._pending_entries = [ ]
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
        initial_options = self._initial_state.options - {simuvex.o.TRACK_CONSTRAINTS} - simuvex.o.refs
        initial_options |= {simuvex.o.SUPER_FASTPATH}
        # initial_options.remove(simuvex.o.COW_STATES)
        self._initial_state.options = initial_options

        starting_points = set()

        rebase_addr = self._binary.rebase_addr

        # clear all existing functions
        self.kb.functions.clear()

        if self._use_symbols:
            starting_points |= set([ addr + rebase_addr for addr in self._function_addresses_from_symbols ])

        if self._extra_function_starts:
            starting_points |= set(self._extra_function_starts)

        # Sort it
        starting_points = sorted(list(starting_points), reverse=True)

        if self.project.entry is not None and self._start <= self.project.entry < self._end:
            # make sure self.project.entry is the first entry
            starting_points += [ self.project.entry ]

        # Create entries for all starting points
        for sp in starting_points:
            self._insert_entry(CFGEntry(sp, sp, 'Ijk_Boring'))

        self._changed_functions = set()

        self._nodes = {}
        self._nodes_by_addr = defaultdict(list)

        if self._use_function_prologues:
            self._function_prologue_addrs = sorted(
                set([addr + rebase_addr for addr in self._func_addrs_from_prologues()])
            )

    def _pre_entry_handling(self, entry):

        # Do not calculate progress if the user doesn't care about the progress at all
        if self._show_progressbar or self._progress_callback:
            max_percentage_stage_1 = 50.0
            percentage = self._seg_list.occupied_size * max_percentage_stage_1 / self._exec_mem_region_size
            if percentage > max_percentage_stage_1:
                percentage = max_percentage_stage_1

            self._update_progress(percentage)

    def _intra_analysis(self):
        pass

    def _get_successors(self, entry):

        current_function_addr = entry.func_addr
        addr = entry.addr
        jumpkind = entry.jumpkind
        src_node = entry.src_node
        src_stmt_idx = entry.src_stmt_idx

        if current_function_addr != -1:
            l.debug("Tracing new exit 0x%08x in function %#08x",
                    addr, current_function_addr)
        else:
            l.debug("Tracing new exit %#08x", addr)

        return self._scan_block(addr, current_function_addr, jumpkind, src_node, src_stmt_idx)

    def _handle_successor(self, entry, successor, successors):
        return [ successor ]

    def _merge_entries(self, *entries):
        pass

    def _widen_entries(self, *entries):
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

    def _post_entry_handling(self, entry, successors):
        pass

    def _entry_list_empty(self):

        if self._pending_entries:

            new_returning_functions = set()
            new_not_returning_functions = set()

            while True:
                new_changes = self._analyze_function_features()

                new_returning_functions |= set(new_changes['functions_return'])
                new_not_returning_functions |= set(new_changes['functions_do_not_return'])

                if not new_changes['functions_do_not_return']:
                    break

            for returning_function in new_returning_functions:
                if returning_function.addr in self._function_returns:
                    for fr in self._function_returns[returning_function.addr]:
                        # Confirm them all
                        self.kb.functions._add_return_from_call(fr.caller_func_addr, fr.callee_func_addr, fr.return_to)

                    del self._function_returns[returning_function.addr]

            for not_returning_function in new_not_returning_functions:
                if not_returning_function.addr in self._function_returns:
                    for fr in self._function_returns[not_returning_function.addr]:
                        # Remove all those FakeRet edges
                        self.kb.functions._remove_fakeret(fr.caller_func_addr, fr.call_site_addr, fr.return_to)

                    del self._function_returns[not_returning_function.addr]

            self._clean_pending_exits(self._pending_entries)

        # Clear _changed_functions set
        self._changed_functions = set()

        if self._pending_entries:
            self._insert_entry(self._pending_entries[0])
            del self._pending_entries[0]
            return

        if self._use_function_prologues and self._function_prologue_addrs:
            while self._function_prologue_addrs:
                prolog_addr = self._function_prologue_addrs[0]
                self._function_prologue_addrs = self._function_prologue_addrs[1:]
                if self._seg_list.is_occupied(prolog_addr):
                    continue

                self._insert_entry(CFGEntry(prolog_addr, prolog_addr, 'Ijk_Boring'))
                return

        # Try to see if there is any indirect jump left to be resolved
        if self._resolve_indirect_jumps and self._indirect_jumps_to_resolve:
            jump_targets = list(set(self._process_indirect_jumps()))

            for addr, func_addr, source_addr in jump_targets:
                r = self._function_add_transition_edge(addr, self._nodes[source_addr], func_addr)
                if r:
                    # TODO: get a better estimate of the function address
                    self._insert_entry(CFGEntry(addr, func_addr, "Ijk_Boring", last_addr=source_addr,
                                                  src_node=self._nodes[source_addr],
                                                  src_stmt_idx=None,
                                                  )
                                         )

            if self._entries:
                return

        if self._force_complete_scan:
            addr = self._next_code_addr()

            if addr is not None:
                self._insert_entry(CFGEntry(addr, addr, "Ijk_Boring", last_addr=None))

    def _post_analysis(self):

        while True:
            new_changes = self._analyze_function_features()
            if not new_changes['functions_do_not_return']:
                break

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
                f.returning = True

        self._remove_redundant_overlapping_blocks()

        if self._normalize:
            # Normalize the control flow graph first before rediscovering all functions
            self.normalize()

        self.make_functions()

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

        # TODO: Make sure self._start is aligned

        # Construct the binary blob first
        # TODO: We shouldn't directly access the _memory of main_bin. An interface
        # TODO: to that would be awesome.

        strides = self._binary.memory.stride_repr

        unassured_functions = []

        for start_, _, bytes_ in strides:
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes_):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        if self._addr_in_exec_memory_regions(self._binary.rebase_addr + position):
                            unassured_functions.append(position)

        return unassured_functions

    # Basic block scanning

    def _scan_block(self, addr, current_function_addr, previous_jumpkind, previous_src_node, previous_src_stmt_idx): #pylint:disable=unused-argument
        """
        Scan a basic block starting at a specific address

        :param addr: The address to begin scanning
        :param current_function_addr: Address of the current function
        :param previous_jumpkind: The jumpkind of the edge going to this node
        :param previous_src_node: The previous CFGNode
        :return: a list of successors
        :rtype: list
        """

        # Fix the function address
        # This is for rare cases where we cannot successfully determine the end boundary of a previous function, and
        # as a consequence, our analysis mistakenly thinks the previous function goes all the way across the boundary,
        # resulting the missing of the second function in function manager.
        if addr in self._function_addresses_from_symbols:
            current_function_addr = addr

        if self.project.is_hooked(addr):
            entries = self._scan_procedure(addr, current_function_addr, previous_jumpkind, previous_src_node,
                                 previous_src_stmt_idx)

        else:
            entries = self._scan_irsb(addr, current_function_addr, previous_jumpkind, previous_src_node,
                                   previous_src_stmt_idx)

        return entries

    def _scan_procedure(self, addr, current_function_addr, previous_jumpkind,  # pylint:disable=unused-argument
                        previous_src_node, previous_src_stmt_idx):
        try:
            hooker = self.project.hooked_by(addr)

            if addr not in self._nodes:
                cfg_node = CFGNode(addr, 0, self, function_address=current_function_addr,
                                   simprocedure_name=hooker.__name__,
                                   no_ret=hooker.NO_RET,
                                   simrun_key=addr,
                                   )

                self._nodes[addr] = cfg_node
                self._nodes_by_addr[addr].append(cfg_node)

            else:
                cfg_node = self._nodes[addr]

            self._graph_add_edge(cfg_node, previous_src_node, previous_jumpkind, previous_src_stmt_idx)

            self._function_add_node(addr, current_function_addr)

            self._changed_functions.add(current_function_addr)

        except (AngrTranslationError, AngrMemoryError):
            return [ ]

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(addr)

        entries = [ ]

        if hooker.ADDS_EXITS:
            # Get two blocks ahead
            grandparent_nodes = self.graph.predecessors(previous_src_node)
            if not grandparent_nodes:
                l.warning("%s is supposed to yield new exits, but it fails to do so.", hooker.__name__)
                return [ ]
            blocks_ahead = [
                self.project.factory.block(grandparent_nodes[0].addr).vex,
                self.project.factory.block(previous_src_node.addr).vex,
            ]
            new_exits = hooker.static_exits(self.project.arch, blocks_ahead)

            for addr, jumpkind in new_exits:
                if isinstance(addr, claripy.ast.BV) and not addr.symbolic:
                    addr = addr._model_concrete.value
                if not isinstance(addr, (int, long)):
                    continue
                entries += self._create_entries(addr, jumpkind, current_function_addr, None, addr, cfg_node, None, None)

        return entries

    def _scan_irsb(self, addr, current_function_addr, previous_jumpkind, previous_src_node, previous_src_stmt_idx):  # pylint:disable=unused-argument
        try:
            # Let's try to create the pyvex IRSB directly, since it's much faster

            irsb = self.project.factory.block(addr).vex

            if irsb.size == 0 and self.project.arch.name in ('ARMHF', 'ARMEL'):
                # maybe the current mode is wrong?
                if addr % 2 == 0:
                    addr_0 = addr + 1
                else:
                    addr_0 = addr - 1
                irsb = self.project.factory.block(addr_0).vex
                if irsb.size > 0:
                    if current_function_addr == addr:
                        current_function_addr = addr_0
                    addr = addr_0

            if irsb.size == 0:
                # decoding error
                return [ ]

            # Occupy the block in segment list
            if irsb.size > 0:
                if self.project.arch.name in ('ARMHF', 'ARMEL') and addr % 2 == 1:
                    # thumb mode
                    real_addr = addr - 1
                else:
                    real_addr = addr
                self._seg_list.occupy(real_addr, irsb.size, "code")

            if addr not in self._nodes:
                # Create a CFG node, and add it to the graph
                cfg_node = CFGNode(addr, irsb.size, self, function_address=current_function_addr, simrun_key=addr,
                                   irsb=irsb)

                self._nodes[addr] = cfg_node
                self._nodes_by_addr[addr].append(cfg_node)

            else:
                cfg_node = self._nodes[addr]

            self._graph_add_edge(cfg_node, previous_src_node, previous_jumpkind, previous_src_stmt_idx)

            self._function_add_node(addr, current_function_addr)

            self._changed_functions.add(current_function_addr)

        except (AngrTranslationError, AngrMemoryError):
            return [ ]

        self._process_block_arch_specific(addr, irsb, current_function_addr)

        # If we have traced it before, don't trace it anymore
        if addr in self._traced_addresses:
            return [ ]
        else:
            # Mark the address as traced
            self._traced_addresses.add(addr)

        # Scan the basic block to collect data references
        if self._collect_data_ref:
            self._collect_data_references(irsb, addr)

        # Get all possible successors
        irsb_next, jumpkind = irsb.next, irsb.jumpkind
        successors = [ ]

        ins_addr = addr
        for i, stmt in enumerate(irsb.statements):
            if isinstance(stmt, pyvex.IRStmt.Exit):
                successors.append((i, ins_addr, stmt.dst, stmt.jumpkind))
            elif isinstance(stmt, pyvex.IRStmt.IMark):
                ins_addr = stmt.addr + stmt.delta

        successors.append(('default', ins_addr, irsb_next, jumpkind))

        entries = [ ]

        successors = self._post_process_successors(addr, successors)

        # Process each successor
        for suc in successors:
            stmt_idx, ins_addr, target, jumpkind = suc

            entries += self._create_entries(target, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx)

        return entries

    def _create_entries(self, target, jumpkind, current_function_addr, irsb, addr, cfg_node, ins_addr, stmt_idx):

        if type(target) is pyvex.IRExpr.Const:  # pylint: disable=unidiomatic-typecheck
            target_addr = target.con.value
        elif type(target) in (pyvex.IRConst.U32, pyvex.IRConst.U64):  # pylint: disable=unidiomatic-typecheck
            target_addr = target.value
        elif type(target) in (int, long):  # pylint: disable=unidiomatic-typecheck
            target_addr = target
        else:
            target_addr = None

        entries = [ ]

        # pylint: disable=too-many-nested-blocks
        if jumpkind == 'Ijk_Boring':
            if target_addr is not None:

                r = self._function_add_transition_edge(target_addr, cfg_node, current_function_addr)

                if not r:
                    if cfg_node is not None:
                        l.debug("An angr exception occurred when adding a transition from %#x to %#x. "
                                  "Ignore this successor.",
                                  cfg_node.addr,
                                  target_addr
                                  )
                    else:
                        l.debug("AngrTranslationError occurred when creating a new entry to %#x. "
                                  "Ignore this successor.",
                                  target_addr
                                  )
                    return []

                ce = CFGEntry(target_addr, current_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                              src_ins_addr=ins_addr, src_stmt_idx=stmt_idx)
                entries.append(ce)

            else:
                l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)
                # Add it to our set. Will process it later if user allows.
                self._indirect_jumps_to_resolve.add(CFGEntry(addr, current_function_addr, jumpkind))

                # Create an IndirectJump instance
                if addr not in self.indirect_jumps:
                    tmp_statements = irsb.statements if stmt_idx == 'default' else irsb.statements[ : stmt_idx]
                    ins_addr = next(iter(stmt.addr for stmt in reversed(tmp_statements)
                                         if isinstance(stmt, pyvex.IRStmt.IMark)), None
                                    )
                    ij = IndirectJump(addr, ins_addr, [ ])
                    self.indirect_jumps[addr] = ij
                else:
                    ij = self.indirect_jumps[addr]

                if irsb:
                    # Test it on the initial state. Does it jump to a valid location?
                    # It will be resolved only if this is a .plt entry
                    tmp_simirsb = simuvex.SimIRSB(self._initial_state, irsb, addr=addr)
                    if len(tmp_simirsb.successors) == 1:
                        tmp_ip = tmp_simirsb.successors[0].ip
                        if tmp_ip._model_concrete is not tmp_ip:
                            tmp_addr = tmp_ip._model_concrete.value
                            tmp_function_addr = tmp_addr # TODO: FIX THIS
                            if (self.project.loader.addr_belongs_to_object(tmp_addr) is not
                                    self.project.loader.main_bin) \
                                    or self.project.is_hooked(tmp_addr):

                                r = self._function_add_transition_edge(tmp_addr, cfg_node, current_function_addr)
                                if r:
                                    ce = CFGEntry(tmp_addr, tmp_function_addr, jumpkind, last_addr=tmp_addr,
                                                  src_node=cfg_node, src_stmt_idx=stmt_idx)
                                    entries.append(ce)

                                    # Fill the IndirectJump object
                                    ij.resolved_targets.add(tmp_addr)

                                    self._function_add_call_edge(tmp_addr, None, None, tmp_function_addr)

        elif jumpkind == 'Ijk_Call' or jumpkind.startswith("Ijk_Sys"):
            is_syscall = jumpkind.startswith("Ijk_Sys")

            if target_addr is not None:
                entries += self._create_entry_call(addr, irsb, cfg_node, stmt_idx, current_function_addr, target_addr,
                                                   jumpkind, is_syscall=is_syscall)

            else:
                resolved, resolved_targets = self._resolve_indirect_jump_timelessly(addr, irsb, current_function_addr)
                if resolved:
                    for t in resolved_targets:
                        entries += self._create_entry_call(addr, irsb, cfg_node, stmt_idx, current_function_addr,
                                                           t, jumpkind, is_syscall=is_syscall)

                else:
                    l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)
                    # Add it to our set. Will process it later if user allows.
                    self._indirect_jumps_to_resolve.add(CFGEntry(addr, current_function_addr, jumpkind))

                    self._create_entry_call(addr, irsb, cfg_node, stmt_idx, current_function_addr, None, jumpkind,
                                            is_syscall=is_syscall)

        elif jumpkind == "Ijk_Ret":
            if current_function_addr != -1:
                self._function_exits[current_function_addr].add(addr)
                self._function_add_return_site(addr, current_function_addr)

            cfg_node.has_return = True

        else:
            # TODO: Support more jumpkinds
            l.debug("Unsupported jumpkind %s", jumpkind)

        return entries

    def _create_entry_call(self, addr, irsb, cfg_node, stmt_idx, current_function_addr, target_addr, jumpkind,
                           is_syscall=False):

        entries = [ ]

        if is_syscall:
            # Fix the target_addr for syscalls
            tmp_path = self.project.factory.path(self.project.factory.blank_state(mode="fastpath",
                                                                                  addr=cfg_node.addr))
            tmp_path.step()
            succ = tmp_path.successors[0]
            _, syscall_addr, _, _ = self.project._simos.syscall_info(succ.state)
            target_addr = syscall_addr

        new_function_addr = target_addr
        if irsb is None:
            return_site = None
        else:
            return_site = addr + irsb.size  # We assume the program will always return to the succeeding position

        if new_function_addr is not None:
            r = self._function_add_call_edge(new_function_addr, cfg_node, return_site, current_function_addr,
                                             syscall=is_syscall)
            if not r:
                return [ ]

        if new_function_addr is not None:
            # Keep tracing from the call
            ce = CFGEntry(target_addr, new_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                          src_stmt_idx=stmt_idx, syscall=is_syscall)
            entries.append(ce)

        if return_site is not None:
            # Also, keep tracing from the return site
            ce = CFGEntry(return_site, current_function_addr, 'Ijk_FakeRet', last_addr=addr, src_node=cfg_node,
                          src_stmt_idx=stmt_idx, returning_source=new_function_addr, syscall=is_syscall)
            self._pending_entries.append(ce)

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

        return entries

    # Data reference processing

    def _collect_data_references(self, irsb, irsb_addr):
        """

        :return:
        """

        # helper methods

        def _process(irsb_, stmt_, data_):
            if type(data_) is pyvex.expr.Const:  # pylint: disable=unidiomatic-typecheck
                val = data_.con.value
                self._add_data_reference(irsb_, irsb_addr, stmt_, val)

        for stmt in irsb.statements:
            if type(stmt) is pyvex.IRStmt.WrTmp:  # pylint: disable=unidiomatic-typecheck
                if type(stmt.data) is pyvex.IRExpr.Load:  # pylint: disable=unidiomatic-typecheck
                    # load
                    # e.g. t7 = LDle:I64(0x0000000000600ff8)
                    _process(irsb, stmt, stmt.data.addr)

                elif type(stmt.data) in (pyvex.IRExpr.Binop, ):  # pylint: disable=unidiomatic-typecheck
                    # binary operation
                    for arg in stmt.data.args:
                        _process(irsb, stmt, arg)

            elif type(stmt) is pyvex.IRStmt.Put:  # pylint: disable=unidiomatic-typecheck
                # put
                # e.g. PUT(rdi) = 0x0000000000400714
                if stmt.offset not in (self._initial_state.arch.ip_offset, ):
                    _process(irsb, stmt, stmt.data)

            elif type(stmt) is pyvex.IRStmt.Store:  # pylint: disable=unidiomatic-typecheck
                # store
                _process(irsb, stmt, stmt.data)

    def _add_data_reference(self, irsb, irsb_addr, stmt, data_addr):  # pylint: disable=unused-argument
        """

        :param irsb:
        :param stmt:
        :param data_addr:
        :return:
        """

        # Make sure data_addr is within a valid memory range
        if data_addr not in self._initial_state.memory:
            return

        data = MemoryData(data_addr, 0, 'unknown', irsb, irsb_addr, stmt)

        self._memory_data[data_addr] = data

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
                    data.max_size = next_data_addr - data_addr
                else:
                    # goes until the end of the section/segment
                    # TODO: the logic needs more testing

                    obj = self.project.loader.addr_belongs_to_object(data_addr)
                    sec = self._addr_belongs_to_section(data_addr)
                    if sec is not None:
                        last_addr = sec.vaddr + sec.memsize + obj.rebase_addr
                    else:
                        seg = self._addr_belongs_to_segment(data_addr)
                        last_addr = seg.vaddr + seg.memsize + obj.rebase_addr
                    data.max_size = last_addr - data_addr

        keys = sorted(self._memory_data.iterkeys())

        new_data_found = False

        i = 0
        # pylint:disable=too-many-nested-blocks
        while i < len(keys):
            data_addr = keys[i]
            i += 1

            memory_data = self._memory_data[data_addr]

            # let's see what sort of data it is
            data_type, data_size = self._guess_data_type(memory_data.irsb, memory_data.irsb_addr, memory_data.stmt_idx,
                                                         data_addr, memory_data.max_size
                                                         )

            if data_type is not None:
                memory_data.size = data_size
                memory_data.sort = data_type

                if memory_data.size < memory_data.max_size:
                    # Create another memory_data object to fill the gap
                    new_addr = data_addr + memory_data.size
                    new_md = MemoryData(new_addr, None, None, None, None, None,
                                        memory_data.max_size - memory_data.size)
                    self._memory_data[new_addr] = new_md
                    keys.insert(i, new_addr)

                if data_type == 'pointer-array':
                    # make sure all pointers are identified
                    pointer_size = self.project.arch.bits / 8
                    buf = self._fast_memory_load(data_addr)

                    # TODO: this part of code is duplicated in _guess_data_type()
                    # TODO: remove the duplication
                    if self.project.arch.memory_endness == 'Iend_LE':
                        fmt = "<"
                    else:
                        fmt = ">"
                    if pointer_size == 8:
                        fmt += "Q"
                    elif pointer_size == 4:
                        fmt += "I"
                    else:
                        raise AngrCFGError("Pointer size of %d is not supported", pointer_size)

                    for j in xrange(0, data_size, pointer_size):
                        ptr_str = self._ffi.unpack(self._ffi.cast('char*', buf + j), pointer_size)
                        ptr = struct.unpack(fmt, ptr_str)[0]  # type:int

                        if self._seg_list.is_occupied(ptr):
                            sort = self._seg_list.occupied_by_sort(ptr)
                            if sort == 'code':
                                continue
                            # TODO: check other sorts
                        if ptr not in self._memory_data:
                            self._memory_data[ptr] = MemoryData(ptr, 0, 'unknown', None, None, None, None)
                            new_data_found = True

            else:
                memory_data.size = memory_data.max_size

        return new_data_found

    def _guess_data_type(self, irsb, irsb_addr, stmt_idx, data_addr, max_size):  # pylint: disable=unused-argument
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

        # some helper methods
        def _c(o):
            return o._model_concrete

        def _cv(o):
            if o._model_concrete is not o:
                return o._model_concrete.value
            return None

        if self._seg_list.is_occupied(data_addr) and self._seg_list.occupied_by_sort(data_addr) == 'code':
            # it's a code reference
            # TODO: Further check if it's the beginning of an instruction
            return "code reference", 0

        pointer_size = self.project.arch.bits / 8

        # who's using it?
        plt_entry = self.project.loader.main_bin.reverse_plt.get(irsb_addr, None)
        if plt_entry is not None:
            # IRSB is owned by plt!
            return "GOT PLT Entry", pointer_size

        # try to decode it as a pointer array
        buf = self._fast_memory_load(data_addr)
        if buf is None:
            # The data address does not exist in static regions
            return None, None

        if self.project.arch.memory_endness == 'Iend_LE':
            fmt = "<"
        else:
            fmt = ">"
        if pointer_size == 8:
            fmt += "Q"
        elif pointer_size == 4:
            fmt += "I"
        else:
            raise AngrCFGError("Pointer size of %d is not supported", pointer_size)

        pointers_count = 0

        max_pointer_array_size = min(512 * pointer_size, max_size)
        for i in xrange(0, max_pointer_array_size, pointer_size):
            ptr_str = self._ffi.unpack(self._ffi.cast('char*', buf + i), pointer_size)
            if len(ptr_str) != pointer_size:
                break

            ptr = struct.unpack(fmt, ptr_str)[0]  # type:int

            if ptr is not None:
                #if self._seg_list.is_occupied(ptr) and self._seg_list.occupied_by_sort(ptr) == 'code':
                #    # it's a code reference
                #    # TODO: Further check if it's the beginning of an instruction
                #    pass
                if self._addr_belongs_to_section(ptr) is not None or self._addr_belongs_to_segment(ptr) is not None:
                    # it's a pointer of some sort
                    # TODO: Determine what sort of pointer it is
                    pointers_count += 1
                else:
                    break

        if pointers_count:
            return "pointer-array", pointer_size * pointers_count

        block = self._fast_memory_load(data_addr)

        # Is it an unicode string?
        # TODO: Support unicode string longer than the max length
        if block[1] == 0 and block[3] == 0 and chr(block[0]) in string.printable:
            max_unicode_string_len = 1024
            unicode_str = self._ffi.string(self._ffi.cast("wchar_t*", block), max_unicode_string_len)
            if len(unicode_str) and all([ c in string.printable for c in unicode_str]):
                return "unicode", (len(unicode_str) + 1) * 2

        # Is it a null-terminated printable string?
        # TODO: Support strings longer than the max length
        max_string_len = 2048
        s = self._ffi.string(self._ffi.cast("char*", block), max_string_len)
        if len(s) and all([ c in string.printable for c in s ]):
            return "string", len(s) + 1

        return None, None

    # Indirect jumps processing

    def _resolve_indirect_jump_timelessly(self, addr, block, func_addr):

        if self.project.arch.name == "MIPS32":
            # Prudently search for indirect jump target
            return self._resolve_indirect_jump_timelessly_mips32(addr, block, func_addr)

        return False, [ ]

    def _resolve_indirect_jump_timelessly_mips32(self, addr, block, func_addr):  # pylint: disable=unused-argument

        b = Blade(self._graph, addr, -1, cfg=self, project=self.project, ignore_sp=True, ignore_bp=True,
                  ignored_regs=('gp',))

        sources = [ n for n in b.slice.nodes() if b.slice.in_degree(n) == 0 ]
        if not sources:
            return False, [ ]

        source = sources[0]
        source_addr = source[0]
        annotated_cfg = AnnotatedCFG(self.project, None, detect_loops=False)
        annotated_cfg.from_digraph(b.slice)

        state = self.project.factory.blank_state(addr=source_addr, mode="fastpath")
        func = self.kb.functions.function(addr=func_addr)
        if 'gp' not in func.info:
            return False, [ ]

        gp_offset = self.project.arch.registers['gp'][0]
        state.regs.gp = func.info['gp']

        def overwrite_tmp_value(state):
            state.inspect.tmp_write_expr = state.se.BVV(func.info['gp'], state.arch.bits)

        # Special handling for cases where `gp` is stored on the stack
        for i, stmt in enumerate(self.project.factory.block(source_addr).vex.statements):
            if isinstance(stmt, pyvex.IRStmt.Put) and stmt.offset == gp_offset and \
                    isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                tmp_offset = stmt.data.tmp  # pylint:disable=cell-var-from-loop
                # we must make sure value of that temporary variable equals to the correct gp value
                state.inspect.make_breakpoint('tmp_write', when=simuvex.BP_BEFORE,
                                              condition=lambda s: s.scratch.bbl_addr == addr and
                                                                  s.scratch.stmt_idx == i and  # pylint:disable=cell-var-from-loop
                                                                  s.inspect.tmp_write_num == tmp_offset,  # pylint:disable=cell-var-from-loop
                                              action=overwrite_tmp_value)

        path = self.project.factory.path(state)
        slicecutor = Slicecutor(self.project, annotated_cfg=annotated_cfg, start=path)

        slicecutor.run()

        if slicecutor.cut:
            suc = slicecutor.cut[0].successors[0].addr

            return True, [ suc ]

        return False, [ ]

    def _process_indirect_jumps(self):
        """
        Resolve indirect jumps found in previous scanning.

        Currently we support resolving the following types of indirect jumps:
        - Ijk_Call (disabled now): indirect calls where the function address is passed in from a proceeding basic block
        - Ijk_Boring: jump tables

        :return: a set of 2-tuples: (resolved indirect jump target, function address)
        :rtype: set
        """

        all_targets = set()
        resolved = set()
        # print "We have %d indirect jumps" % len(self._indirect_jumps)

        for entry in self._indirect_jumps_to_resolve:

            resolved.add(entry)

            # is it a jump table? try with the fast approach
            resolvable, targets = self._resolve_jump_table_fast(entry.addr, entry.jumpkind)
            if resolvable:
                # Remove all targets that don't make sense
                targets = [ t for t in targets if any(iter((a <= t < b) for a, b in self._exec_mem_regions)) ]

                if entry.addr in self.indirect_jumps:
                    ij = self.indirect_jumps[entry.addr]

                    ij.jumptable = True

                    # Fill the IndirectJump object
                    ij.resolved_targets |= set(targets)

                all_targets |= set([ (t, entry.func_addr, entry.addr) for t in targets ])
                continue

            # is it a slightly more complex jump table? try the slow approach
            # resolvable, targets = self._resolve_jump_table_accurate(addr, jumpkind)
            # if resolvable:
            #    all_targets |= set(targets)
            #    continue

        for t in resolved:
            self._indirect_jumps_to_resolve.remove(t)

        return all_targets

    def _resolve_jump_table_fast(self, addr, jumpkind):
        """
        Check if the indirect jump is a jump table, and if it is, resolve it and return all possible targets.

        This is a fast jump table resolution. For performance concerns, we made the following assumptions:
        - The final jump target comes from the memory.
        - The final jump target must be directly read out of the memory, without any further modification or altering.

        :param int addr: the address of the basic block
        :param str jumpkind: the jump kind of the indirect jump
        :return: a bool indicating whether the indirect jump is resolved successfully, and a list of resolved targets
        :rtype: tuple
        """

        if jumpkind != "Ijk_Boring":
            # Currently we only support boring ones
            return False, None

        # Perform a backward slicing from the jump target
        b = Blade(self.graph, addr, -1, cfg=self, project=self.project, ignore_sp=True, ignore_bp=True, max_level=2)

        stmt_loc = (addr, 'default')
        if stmt_loc not in b.slice:
            return False, None

        load_stmt_loc, load_stmt = None, None
        past_stmts = [ stmt_loc ]
        while True:
            preds = b.slice.predecessors(stmt_loc)
            if len(preds) != 1:
                return False, None
            block_addr, stmt_idx = preds[0]
            block = self.project.factory.block(block_addr).vex
            stmt = block.statements[stmt_idx]
            if isinstance(stmt, pyvex.IRStmt.WrTmp) or isinstance(stmt, pyvex.IRStmt.Put):
                if isinstance(stmt.data, pyvex.IRExpr.Get) or isinstance(stmt.data, pyvex.IRExpr.RdTmp):
                    # data transferring
                    past_stmts.append(stmt_loc)
                    stmt_loc = (block_addr, stmt_idx)
                    continue
                elif isinstance(stmt.data, pyvex.IRExpr.Load):
                    # Got it!
                    stmt_loc = (block_addr, stmt_idx)
                    load_stmt, load_stmt_loc = stmt, stmt_loc
                    past_stmts.append(stmt_loc)
            break

        if load_stmt_loc is None:
            # the load statement is not found
            return False, None

        # skip all statements before the load statement
        b.slice.remove_nodes_from(past_stmts)

        # Debugging output
        # for addr, stmt_idx in sorted(list(b.slice.nodes())):
        #    irsb = self.project.factory.block(addr).vex
        #    stmts = irsb.statements
        #    print "%x: %d | " % (addr, stmt_idx),
        #    print "%s" % stmts[stmt_idx],
        #    print "%d" % b.slice.in_degree((addr, stmt_idx))
        # print ""

        # Get all sources
        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]

        # Create the annotated CFG
        annotatedcfg = AnnotatedCFG(self.project, None, detect_loops=False)
        annotatedcfg.from_digraph(b.slice)

        # pylint: disable=too-many-nested-blocks
        for src_irsb, _ in sources:
            # Use slicecutor to execute each one, and get the address
            # We simply give up if any exception occurs on the way

            start_state = self.project.factory.blank_state(
                    addr=src_irsb,
                    mode='static',
                    add_options={
                        simuvex.o.DO_RET_EMULATION,
                        simuvex.o.TRUE_RET_EMULATION_GUARD,
                        simuvex.o.AVOID_MULTIVALUED_READS,
                    },
                    remove_options={
                        simuvex.o.CGC_ZERO_FILL_UNCONSTRAINED_MEMORY,
                        simuvex.o.UNINITIALIZED_ACCESS_AWARENESS,
                    }
            )
            start_state.regs.bp = start_state.arch.initial_sp + 0x2000

            start_path = self.project.factory.path(start_state)

            # Create the slicecutor
            slicecutor = Slicecutor(self.project, annotatedcfg, start=start_path, targets=(load_stmt_loc[0],))

            # Run it!
            try:
                slicecutor.run()
            except KeyError as ex:
                # This is because the program slice is incomplete.
                # Blade will support more IRExprs and IRStmts
                l.debug("KeyError occurred due to incomplete program slice.", exc_info=ex)
                continue

            # Get the jumping targets
            for r in slicecutor.deadended:

                all_states = r.next_run.unsat_successors
                state = all_states[0] # Just take the first state

                # Parse the memory load statement
                load_addr_tmp = load_stmt.data.addr.tmp
                if load_addr_tmp not in state.scratch.temps:
                    # the tmp variable is not there... umm...
                    continue
                jump_addr = state.scratch.temps[load_addr_tmp]
                total_cases = jump_addr._model_vsa.cardinality
                all_targets = [ ]

                if total_cases > self._indirect_jump_target_limit:
                    # We resolved too many targets for this indirect jump. Something might have gone wrong.
                    l.debug("%d targets are resolved for the indirect jump at %#x. It may not be a jump table",
                              total_cases, addr)
                    return False, None

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.se.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr +
                    # (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                for idx, a in enumerate(state.se.any_n_int(jump_addr, total_cases)):
                    if idx % 100 == 0:
                        l.debug("Resolved %d targets for the indirect jump at %#x", idx, addr)
                    jump_target = state.memory.load(a, state.arch.bits / 8, endness=state.arch.memory_endness)
                    target = state.se.any_int(jump_target)
                    all_targets.append(target)
                    jump_table.append(target)

                l.info("Jump table resolution: resolved %d targets from %#x", len(all_targets), addr)

                ij = self.indirect_jumps[addr]
                ij.jumptable = True
                ij.jumptable_addr = state.se.min(jump_addr)
                ij.jumptable_targets = jump_table
                ij.jumptable_entries = total_cases

                return True, all_targets

        return False, None

    def _resolve_jump_table_accurate(self, addr, jumpkind):
        """
        Check if the indirect jump is a jump table, and if it is, resolve it and return all possible targets.

        This is the accurate (or rather, slower) version jump table resolution.

        :param int addr: the address of the basic block
        :param str jumpkind: the jump kind of the indirect jump
        :return: a bool indicating whether the indirect jump is resolved successfully, and a list of resolved targets
        :rtype: tuple
        """

        if jumpkind != "Ijk_Boring":
            # Currently we only support boring ones
            return False, None

        # Perform a backward slicing from the jump target
        b = Blade(self.graph, addr, -1, cfg=self, project=self.project, ignore_sp=True, ignore_bp=True)

        # Debugging output
        # for addr, stmt_idx in sorted(list(b.slice.nodes())):
        #    irsb = self.project.factory.block(addr).vex
        #    stmts = irsb.statements
        #    print "%x: %d | " % (addr, stmt_idx),
        #    print "%s" % stmts[stmt_idx],
        #    print "%d" % b.slice.in_degree((addr, stmt_idx))
        # print ""

        # Get all sources
        sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]

        # Create the annotated CFG
        annotatedcfg = AnnotatedCFG(self.project, None, detect_loops=False)
        annotatedcfg.from_digraph(b.slice)

        for src_irsb, _ in sources:
            # Use slicecutor to execute each one, and get the address
            # We simply give up if any exception occurs on the way

            start_state = self.project.factory.blank_state(
                    addr=src_irsb,
                    mode='static',
                    add_options={
                        simuvex.o.DO_RET_EMULATION,
                        simuvex.o.TRUE_RET_EMULATION_GUARD,
                        simuvex.o.KEEP_MEMORY_READS_DISCRETE, # Please do not merge values that are read out of the
                                                              # memory
                    }
            )
            start_state.regs.bp = start_state.arch.initial_sp + 0x2000

            start_path = self.project.factory.path(start_state)

            # Create the slicecutor
            slicecutor = Slicecutor(self.project, annotatedcfg, start=start_path, targets=(addr,))

            # Run it!
            try:
                slicecutor.run()
            except KeyError as ex:
                # This is because the program slice is incomplete.
                # Blade will support more IRExprs and IRStmts
                l.debug("KeyError occurred due to incomplete program slice.", exc_info=ex)
                continue

            # Get the jumping targets
            for r in slicecutor.reached_targets:

                all_states = r.unconstrained_successor_states + [ s.state for s in r.successors ]
                state = all_states[0]
                jump_target = state.ip

                total_cases = jump_target._model_vsa.cardinality
                all_targets = [ ]

                if total_cases > self._indirect_jump_target_limit:
                    # We resolved too many targets for this indirect jump. Something might have gone wrong.
                    l.debug("%d targets are resolved for the indirect jump at %#x. It may not be a jump table",
                              total_cases, addr)
                    return False, None

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.se.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr +
                    # (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                for idx, target in enumerate(state.se.any_n_int(jump_target, total_cases)):
                    if idx % 100 == 0:
                        l.debug("Resolved %d targets for the indirect jump at %#x", idx, addr)
                    all_targets.append(target)
                    jump_table.append(target)

                    l.info("Jump table resolution: resolved %d targets from %#x", len(all_targets), addr)

                    ij = self.indirect_jumps[addr]
                    ij.jumptable = True
                    ij.jumptable_addr = state.se.min(jump_target)
                    ij.jumptable_targets = jump_table
                    ij.jumptable_entries = total_cases

                    return True, all_targets

    def _resolve_indirect_calls(self):
        """

        :return:
        """

        # TODO: Fix and enable this method later

        function_starts = set()

        for jumpkind, irsb_addr in self._indirect_jumps_to_resolve:
            # First execute the current IRSB in concrete mode

            if len(function_starts) > 20:
                break

            if jumpkind == "Ijk_Call":
                state = self.project.factory.blank_state(addr=irsb_addr, mode="concrete",
                                                         add_options={simuvex.o.SYMBOLIC_INITIAL_VALUES}
                                                         )
                path = self.project.factory.path(state)
                print hex(irsb_addr)

                try:
                    r = (path.next_run.successors + path.next_run.unsat_successors)[0]
                    ip = r.se.exactly_n_int(r.ip, 1)[0]

                    function_starts.add(ip)
                    continue
                except simuvex.SimSolverModeError:
                    pass

                # Not resolved
                # Do a backward slicing from the call
                irsb = self.project.factory.block(irsb_addr).vex

                # Start slicing from the "next"
                b = Blade(self.graph, irsb.addr, -1, project=self.project)

                # Debugging output
                for addr, stmt_idx in sorted(list(b.slice.nodes())):
                    irsb = self.project.factory.block(addr).vex
                    stmts = irsb.statements
                    print "%x: %d | " % (addr, stmt_idx),
                    print "%s" % stmts[stmt_idx],
                    print "%d" % b.slice.in_degree((addr, stmt_idx))

                print ""

                # Get all sources
                sources = [n for n in b.slice.nodes() if b.slice.in_degree(n) == 0]

                # Create the annotated CFG
                annotatedcfg = AnnotatedCFG(self.project, None, detect_loops=False)
                annotatedcfg.from_digraph(b.slice)

                for src_irsb, _ in sources:
                    # Use slicecutor to execute each one, and get the address
                    # We simply give up if any exception occurs on the way

                    start_state = self.project.factory.blank_state(
                            addr=src_irsb,
                            add_options={
                                simuvex.o.DO_RET_EMULATION,
                                simuvex.o.TRUE_RET_EMULATION_GUARD
                            }
                    )

                    start_path = self.project.factory.path(start_state)

                    # Create the slicecutor
                    slicecutor = Slicecutor(self.project, annotatedcfg, start=start_path, targets=(irsb_addr,))

                    # Run it!
                    try:
                        slicecutor.run()
                    except KeyError as ex:
                        # This is because the program slice is incomplete.
                        # Blade will support more IRExprs and IRStmts
                        l.debug("KeyError occurred due to incomplete program slice.", exc_info=ex)
                        continue

                    # Get the jumping targets
                    for r in slicecutor.reached_targets:
                        if r.next_run.successors:
                            target_ip = r.next_run.successors[0].ip
                            se = r.next_run.successors[0].se

                            if not se.symbolic(target_ip):
                                concrete_ip = se.exactly_n_int(target_ip, 1)[0]
                                function_starts.add(concrete_ip)
                                l.info("Found a function address %x", concrete_ip)

        return function_starts

    # Removers

    def _remove_redundant_overlapping_blocks(self):
        """
        On X86 and AMD64 there are sometimes garbage bytes (usually nops) between functions in order to properly
        align the succeeding function. CFGFast does a linear sweeping which might create duplicated blocks for
        function epilogues where one block starts before the garbage bytes and the other starts after the garbage bytes.

        This method enumerates all blocks and remove overlapping blocks if one of them is aligned to 0x10 and the other
        contains only garbage bytes.

        :return: None
        """

        sorted_nodes = sorted(self.graph.nodes(), key=lambda n: n.addr if n is not None else 0)

        # go over the list. for each node that is the beginning of a function and is not properly aligned, if its
        # leading instruction is a single-byte or multi-byte nop, make sure there is another CFGNode starts after the
        # nop instruction

        nodes_to_append = {}
        # pylint:disable=too-many-nested-blocks
        for a in sorted_nodes:
            if a.addr % 0x10 != 0 and a.addr in self.functions and (a.size > 0x10 - (a.addr % 0x10)):
                all_in_edges = self.graph.in_edges(a, data=True)
                if not any([data['jumpkind'] == 'Ijk_Call' for _, _, data in all_in_edges]):
                    # no one is calling it
                    # this function might be created from linear sweeping
                    try:
                        block = self.project.factory.block(a.addr, max_size=0x10 - (a.addr % 0x10))
                    except AngrTranslationError:
                        continue
                    if len(block.capstone.insns) == 1 and block.capstone.insns[0].insn_name() == "nop":
                        # leading nop for alignment.
                        next_node_addr = a.addr + 0x10 - (a.addr % 0x10)
                        if not (next_node_addr in self._nodes or next_node_addr in nodes_to_append):
                            # create a new CFGNode that starts there
                            next_node = CFGNode(next_node_addr, a.size - (0x10 - (a.addr % 0x10)), self,
                                                function_address=next_node_addr
                                                )
                            # create edges accordingly
                            all_out_edges = self.graph.out_edges(a, data=True)
                            for _, dst, data in all_out_edges:
                                self.graph.add_edge(next_node, dst, **data)

                            nodes_to_append[next_node_addr] = next_node

                            # make sure there is a function begins there
                            self.functions._add_node(next_node_addr, next_node_addr)

        # append all new nodes to sorted nodes
        if nodes_to_append:
            sorted_nodes = sorted(sorted_nodes + nodes_to_append.values(), key=lambda n: n.addr if n is not None else 0)

        for i in xrange(len(sorted_nodes) - 1):

            a, b = sorted_nodes[i], sorted_nodes[i + 1]

            if a is None or b is None:
                continue

            if a.addr <= b.addr and \
                    (a.addr + a.size > b.addr):
                # They are overlapping
                if b.addr in self.kb.functions and (b.addr - a.addr < 0x10) and b.addr % 0x10 == 0:
                    # b is the beginning of a function
                    # a should be shrinked
                    self._shrink_node(a, b.addr - a.addr)

                else:
                    try:
                        block = self.project.factory.block(a.addr, max_size=b.addr - a.addr)
                    except AngrTranslationError:
                        continue
                    if len(block.capstone.insns) == 1 and block.capstone.insns[0].insn_name() == "nop":
                        # It's a big nop
                        self._shrink_node(a, b.addr - a.addr)

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

    def _shrink_node(self, node, new_size):
        """
        Shrink the size of a node in CFG.

        :param CFGNode node: The CFGNode to shrink
        :param int new_size: The new size of the basic block
        :return: None
        """

        # Generate the new node
        new_node = CFGNode(node.addr, new_size, self, function_address=node.function_address)

        old_edges = self.graph.in_edges(node, data=True)

        for src, _, data in old_edges:
            self.graph.add_edge(src, new_node, data)

        successor_node_addr = node.addr + new_size
        if successor_node_addr in self._nodes:
            successor = self._nodes[successor_node_addr]
            self.graph.add_edge(new_node, successor, jumpkind='Ijk_Boring')

        self._nodes[new_node.addr] = new_node

        # the function starting at this point is probably totally incorrect
        # hopefull future call to `make_functions()` will correct everything
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

        if node.addr in self.kb.functions.callgraph:
            self.kb.functions.callgraph.remove_node(node.addr)

    def _clean_pending_exits(self, pending_exits):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning syscalls
        b) they are the return exits of non-returning functions

        :param pending_exits: A list of all pending exits
        :return: None
        """

        pending_exits_to_remove = []

        for i, pe in enumerate(pending_exits):

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
            del pending_exits[index]

    #
    # Graph utils
    #

    def _graph_add_edge(self, cfg_node, src_node, src_jumpkind, src_stmt_idx):
        if src_node is None:
            self.graph.add_node(cfg_node)
        else:
            self.graph.add_edge(src_node, cfg_node, jumpkind=src_jumpkind,
                                stmt_idx=src_stmt_idx)

    #
    # Function utils
    #

    def _function_add_node(self, addr, function_addr):
        self.kb.functions._add_node(function_addr, addr)

    def _function_add_transition_edge(self, addr, src_node, function_addr):
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
            # Add this basic block into the function manager
            if src_node is None:
                self.kb.functions._add_node(function_addr, addr)
            else:
                self.kb.functions._add_transition_to(function_addr, src_node.addr, addr)
            return True
        except (AngrMemoryError, AngrTranslationError):
            return False

    def _function_add_call_edge(self, addr, src_node, ret_addr, function_addr, syscall=False):
        """
        Add a call edge to the function transition map.

        :param int addr: Address that is being called (callee).
        :param CFGNode src_node: The source CFG node (caller).
        :param int ret_addr: Address that returns to (in case the function returns).
        :param int function_addr: Function address..
        :param bool syscall: If this is a call to a syscall or not.
        :return: True if the edge is added. False if any exception occurred.
        :rtype: bool
        """
        try:
            if src_node is None:
                self.kb.functions._add_node(function_addr, addr, syscall=syscall)
            else:
                self.kb.functions._add_call_to(function_addr, src_node.addr, addr, ret_addr, syscall=syscall)
            return True
        except (AngrMemoryError, AngrTranslationError):
            return False

    def _function_add_fakeret_edge(self, addr, src_node, function_addr, confirmed=None):
        if src_node is None:
            self.kb.functions._add_node(function_addr, addr)
        else:
            self.kb.functions._add_fakeret_to(function_addr, src_node.addr, addr, confirmed=confirmed)

    def _function_add_return_site(self, addr, function_addr):
        self.kb.functions._add_return_from(function_addr, addr)

    def _function_add_return_edge(self, return_from_addr, return_to_addr, function_addr):
        self.kb.functions._add_return_from_call(function_addr, return_from_addr, return_to_addr)

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
        tmp_irsb = self.project.factory.block(last_imark.addr + last_imark.delta).vex
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

    def _process_block_arch_specific(self, addr, irsb, func_addr):  # pylint: disable=unused-argument

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
            if addr == func_addr:
                # Prudently search for $gp values
                state = self.project.factory.blank_state(addr=addr, mode="fastpath")
                state.regs.t9 = func_addr
                state.regs.gp = 0xffffffff
                p = self.project.factory.path(state)
                p.step(num_inst=3)

                if not p.successors:
                    return

                state = p.successors[0].state
                if not state.regs.gp.symbolic and state.se.is_false(state.regs.gp == 0xffffffff):
                    self.kb.functions.function(func_addr).info['gp'] = state.regs.gp._model_concrete.value

    #
    # Public methods
    #

    def copy(self):
        n = CFGFast.__new__(CFGFast)

        n._binary = self._binary
        n._start = self._start
        n._end = self._end
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
        n._exec_mem_region_size = self._exec_mem_region_size[::]

        n._memory_data = self._memory_data.copy()

        n._seg_list = self._seg_list.copy()

        n._function_addresses_from_symbols = self._function_addresses_from_symbols

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
