import logging
import string
import math
import re
from datetime import datetime
from collections import defaultdict

import networkx
import progressbar

import simuvex
import pyvex

from ..analysis import Analysis, register_analysis
from ..surveyors import Slicecutor
from ..annocfg import AnnotatedCFG
from .cfg_base import CFGBase

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
                            self._list[ segment_pos + 1 : ]
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
        if address >= self._list[idx].start and address < self._list[idx].end:
            return True
        if idx > 0 and address < self._list[idx - 1].end:
            return True
        return False

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


class MemoryData(object):
    def __init__(self, address, size, sort):
        self.address = address
        self.size = size
        self.sort = sort

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

    def __init__(self, addr, func_addr, jumpkind, ret_target=None, last_addr=None, src_node=None, src_stmt_idx=None):
        self.addr = addr
        self.func_addr = func_addr
        self.jumpkind = jumpkind
        self.ret_target = ret_target
        self.last_addr = last_addr
        self.src_node = src_node
        self.src_stmt_idx = src_stmt_idx


class CFGFast(Analysis, CFGBase):
    """
    We find functions inside the given binary, and build a control-flow graph in very fast manners: instead of
    simulating program executions, keeping track of states, and performing expensive data-flow analysis, CFGFast will
    only perform light-weight analyses combined with some heuristics, and with some strong assumptions.

    # TODO: Write about what analysis techniques and heuristics are used

    Due to the nature of those techniques that are used here, a base address is often not required to use this analysis
    routine. However, with a correct base address, CFG recovery will almost always yield a much better result. A custom
    analysis, called GirlScout, is specifically made to recover the base address of a binary blob. After the base
    address is determined, you may want to reload the binary with the new base address by creating a new Project object,
    and then re-recover the CFG.
    """

    def __init__(self,
                 binary=None,
                 start=None,
                 end=None,
                 pickle_intermediate_results=False,
                 symbols=True,
                 function_prologues=True,
                 resolve_indirect_jumps=False,
                 force_segment=False,
                 force_complete_scan=True,
                 indirect_jump_target_limit=100000,
                 collect_data_references=False,
                 progress_callback=None,
                 show_progressbar=False
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
        :param progress_callback:       Specify a callback function to get the progress during CFG recovery.
        :param bool show_progressbar:   Should CFGFast show a progressbar during CFG recovery or not.
        :return: None
        """

        CFGBase.__init__(self, self.project, 0)

        self._binary = binary if binary is not None else self.project.loader.main_bin
        self._start = start if start is not None else (self._binary.rebase_addr + self._binary.get_min_addr())
        self._end = end if end is not None else (self._binary.rebase_addr + self._binary.get_max_addr())

        self._pickle_intermediate_results = pickle_intermediate_results
        self._indirect_jump_target_limit = indirect_jump_target_limit
        self._collect_data_ref = collect_data_references

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self._force_segment = force_segment
        self._force_complete_scan = force_complete_scan

        self._progress_callback = progress_callback
        self._show_progressbar = show_progressbar

        self._progressbar = None  # will be initialized later if self._show_progressbar == True

        l.debug("Starts at %#x and ends at %#x.", self._start, self._end)

        # Get all executable memory regions
        self._exec_mem_regions = self._executable_memory_regions(self._binary, self._force_segment)
        self._exec_mem_region_size = sum([(end - start) for start, end in self._exec_mem_regions])

        # A mapping between (address, size) and the actual data in memory
        self._memory_data = { }

        self._initial_state = None
        self._next_addr = self._start - 1

        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

        # All IRSBs with an indirect exit target
        self._indirect_jumps = set()

        self._jump_tables = { }

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
    # Public methods
    #
    @property
    def functions(self):
        return self.kb.functions

    #
    # Private methods
    #

    def __setstate__(self, s):
        self._graph = s['graph']
        self._jump_tables = s['jump_tables']

    def __getstate__(self):
        s = {
            "graph": self.graph,
            "jump_tables": self._jump_tables,
        }
        return s

    def _addr_in_memory_regions(self, addr):
        """
        Check if the rebased address locates inside any of the valid memory regions
        :param addr: A rebased address
        :return: True/False
        """

        for start, end in self._exec_mem_regions:
            if addr < start:
                # The list is ordered!
                break

            if addr >= start and addr < end:
                return True

        return False

    def _initialize_progressbar(self):
        """
        Initialize the progressbar.
        :return: None
        """

        widgets = [progressbar.Percentage(),
                   ' ',
                   progressbar.Bar(marker=progressbar.RotatingMarker()),
                   ' ',
                   progressbar.Timer(),
                   ' ',
                   progressbar.ETA()
                   ]

        self._progressbar = progressbar.ProgressBar(widgets=widgets, maxval=10000 * 100).start()

    def _update_progressbar(self, percentage):
        """
        Update the progressbar with a percentage.

        :param float percentage: Percentage of the progressbar. from 0.0 to 100.0.
        :return: None
        """

        if self._progressbar is not None:
            self._progressbar.update(percentage * 10000)

    def _finish_progressbar(self):
        """
        Mark the progressbar as finished.
        :return: None
        """

        if self._progressbar is not None:
            self._progressbar.finish()

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
            if curr_addr >= start and curr_addr < end:
                # accept
                accepted = True
                break
            if curr_addr < start:
                # accept, but we are skipsping the gap
                accepted = True
                curr_addr = start

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

    # Methods to get start points for scanning

    def _func_addrs_from_symbols(self):
        """
        Get all possible function addresses that are specified by the symbols in the binary

        :return: A list of addresses that are probably functions
        """

        symbols_by_addr = self._binary.symbols_by_addr

        func_addrs = []

        for addr, sym in symbols_by_addr.iteritems():
            if sym.is_function:
                func_addrs.append(addr)

        return func_addrs

    def _func_addrs_from_prologues(self):
        """
        Scan the entire program image for function prologues, and start code scanning at those positions

        :return: A list of possible function addresses
        """

        # Pre-compile all regexes
        regexes = set()
        for ins_regex in self.project.arch.function_prologs:
            r = re.compile(ins_regex)
            regexes.add(r)

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
                        if self._addr_in_memory_regions(self._binary.rebase_addr + position):
                            unassured_functions.append(position)

        return unassured_functions

    # Basic block scanning

    def _scan_code(self, traced_addresses, function_exits, starting_address, maybe_function): #pylint:disable=unused-argument
        # Saving tuples like (current_function_addr, next_exit_addr)
        # Current_function_addr == -1 for exits not inside any function
        remaining_entries = set()
        next_addr = starting_address

        # Initialize the remaining_entries set
        ce = CFGEntry(next_addr, next_addr, 'Ijk_Boring', last_addr=None)
        remaining_entries.add(ce)

        while len(remaining_entries):
            ce = remaining_entries.pop()

            current_function_addr = ce.func_addr
            addr = ce.addr
            jumpkind = ce.jumpkind
            src_node = ce.src_node
            src_stmt_idx = ce.src_stmt_idx

            if current_function_addr != -1:
                l.debug("Tracing new exit 0x%08x in function 0x%08x",
                        addr, current_function_addr)
            else:
                l.debug("Tracing new exit 0x%08x", addr)

            self._scan_block(addr, current_function_addr, function_exits, remaining_entries, traced_addresses,
                             jumpkind, src_node, src_stmt_idx)

    def _scan_block(self, addr, current_function_addr, function_exits, remaining_entries, traced_addresses,
                    previous_jumpkind, previous_src_node, previous_src_stmt_idx): #pylint:disable=unused-argument
        """
        Scan a basic block starting at a specific address

        :param addr: The address to begin scanning
        :param current_function_addr: Address of the current function
        :param function_exits: Exits of the current function
        :param remaining_entries: Remaining exits
        :param traced_addresses: Addresses that have already been traced
        :param previous_jumpkind: The jumpkind of the edge going to this node
        :param previous_src_node: The previous CFGNode
        :return: None
        """

        # If we have traced it before, don't trace it anymore
        if addr in traced_addresses:
            return

        try:
            # Let's try to create the pyvex IRSB directly, since it's much faster

            irsb = self.project.factory.block(addr).vex

            # Create a CFG node, and add it to the graph
            cfg_node = CFGNode(addr, irsb.size, self, function_address=current_function_addr)
            if previous_src_node is None:
                self.graph.add_node(cfg_node)
            else:
                self.graph.add_edge(previous_src_node, cfg_node, jumpkind=previous_jumpkind,
                                    stmt_idx=previous_src_stmt_idx)

            # Add this basic block into the function manager
            if previous_src_node is None:
                self.kb.functions._add_node(current_function_addr, addr)
            else:
                self.kb.functions._add_transition_to(current_function_addr, previous_src_node.addr, addr)

            # Occupy the block in segment list
            if irsb.size > 0:
                self._seg_list.occupy(addr, irsb.size, "code")

        except (AngrTranslationError, AngrMemoryError):
            return

        # Mark the address as traced
        traced_addresses.add(addr)

        # Scan the basic block to collect data references
        if self._collect_data_ref:
            self._collect_data_references(irsb)

        # Get all possible successors
        irsb_next, jumpkind = irsb.next, irsb.jumpkind
        successors = [(i, stmt.dst, stmt.jumpkind) for i, stmt in enumerate(irsb.statements) if type(stmt) is pyvex.IRStmt.Exit]
        successors.append(('default', irsb_next, jumpkind))

        # Process each successor
        for suc in successors:
            stmt_idx, target, jumpkind = suc

            if type(target) is pyvex.IRExpr.Const:
                next_addr = target.con.value
            elif type(target) in (pyvex.IRConst.U32, pyvex.IRConst.U64):
                next_addr = target.value
            else:
                next_addr = None

            if jumpkind == 'Ijk_Boring':
                if next_addr is not None:
                    ce = CFGEntry(next_addr, current_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                                  src_stmt_idx = stmt_idx)
                    remaining_entries.add(ce)

                else:
                    l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)
                    # Add it to our set. Will process it later if user allows.
                    self._indirect_jumps.add((addr, jumpkind))

            elif jumpkind == 'Ijk_Call':
                if next_addr is not None:

                    new_function_addr = next_addr
                    return_site = addr + irsb.size  # We assume the program will always return to the succeeding position

                    if current_function_addr != -1:
                        self.kb.functions._add_call_to(
                            current_function_addr,
                            addr,
                            next_addr,
                            return_site
                        )

                    # Keep tracing from the call
                    ce = CFGEntry(next_addr, new_function_addr, jumpkind, last_addr=addr, src_node=cfg_node,
                                  src_stmt_idx=stmt_idx)
                    remaining_entries.add(ce)
                    # Also, keep tracing from the return site
                    ce = CFGEntry(return_site, current_function_addr, 'Ijk_Ret', last_addr=addr, src_node=cfg_node,
                                  src_stmt_idx=stmt_idx)
                    remaining_entries.add(ce)

                else:
                    l.debug('(%s) Indirect jump at %#x.', jumpkind, addr)

                    # Add it to our set. Will process it later if user allows.
                    self._indirect_jumps.add((addr, jumpkind))

            elif jumpkind == "Ijk_Ret":
                if current_function_addr != -1:
                    function_exits[current_function_addr].add(next_addr)

            else:
                # TODO: Support more jumpkinds
                l.debug("Unsupported jumpkind %s", jumpkind)

    def _collect_data_references(self, irsb):
        """

        :return:
        """

        # helper methods

        def _process(irsb_, stmt_, data_):
            if type(data_) is pyvex.expr.Const:
                val = data_.con.value
                self._add_data_reference(irsb_, stmt_, val)

        for stmt in irsb.statements:
            if type(stmt) is pyvex.IRStmt.WrTmp:
                if type(stmt.data) is pyvex.IRExpr.Load:
                    # load
                    # e.g. t7 = LDle:I64(0x0000000000600ff8)
                    _process(irsb, stmt, stmt.data.addr)

            elif type(stmt) is pyvex.IRStmt.Put:
                # put
                # e.g. PUT(rdi) = 0x0000000000400714
                if stmt.offset not in (self._initial_state.arch.ip_offset, ):
                    _process(irsb, stmt, stmt.data)

    def _add_data_reference(self, irsb, stmt, data_addr):
        """

        :param irsb:
        :param stmt:
        :param data_addr:
        :return:
        """

        # Make sure data_addr is within a valid memory range
        if data_addr not in self._initial_state.memory:
            return

        # First, let's see what sort of data it is
        data_type, data_size = self._guess_data_type(data_addr)

        data = MemoryData(data_addr, data_size, data_type)

        self._memory_data[(data_addr, data_size)] = data

    def _guess_data_type(self, data_addr):
        """

        :param data_addr:
        :return:
        """

        # some helper methods
        def _c(o):
            return o._model_concrete

        def _cv(o):
            if o._model_concrete is not o:
                return o._model_concrete.value
            return None

        block = self._initial_state.memory.load(data_addr, 8)

        # Is it an unicode string?
        if _cv(block[1]) == 0 and _cv(block[3]) == 0:
            if chr(_cv(block[0])) in string.printable and chr(_cv(block[2])) in string.printable + "\x00":
                r, c, m = self._initial_state.memory.find(data_addr, "\x00\x00", max_search=4096)

                if c and _c(c[0]) is True and _cv(r) - data_addr > 0:
                    length = _cv(r) - data_addr
                    block_ = self._initial_state.memory.load(data_addr, length)

                    if all([ chr(_cv(block[i*8+7:i*8])) in string.printable for i in xrange(len(block_) / 8, 2) ]) and \
                        all([ _cv(block[i*8+7:i*8]) == 0 for i in xrange(1, len(block_) / 8, 2) ]):
                        return "unicode", length + 2

        # Is it a null-terminated printable string?
        r, c, m = self._initial_state.memory.find(data_addr, "\x00", max_search=4096)

        if c and _c(c[0]) is True and _cv(r) - data_addr > 0:
            # TODO: Add a cap for the length
            length = _cv(r) - data_addr
            block_ = self._initial_state.memory.load(data_addr, length)
            if all([ (_cv(block_[i*8+7:i*8]) is not None and chr(_cv(block_[i*8+7:i*8])) in string.printable)
                     for i in xrange(len(block_) / 8) ]):
                return "string", length + 1

        return "unknown", 0

    def _process_indirect_jumps(self):
        """
        Resolve indirect jumps found in previous scanning.

        Currently we support resolving the following types of indirect jumps:
        - Ijk_Call (disabled now): indirect calls where the function address is passed in from a proceeding basic block
        - Ijk_Boring: jump tables

        :return: a set of newly resolved indirect jumps
        :rtype: set
        """

        all_targets = set()
        resolved = set()
        # print "We have %d indirect jumps" % len(self._indirect_jumps)

        for addr, jumpkind in self._indirect_jumps:

            resolved.add((addr, jumpkind))

            # is it a jump table? try with the fast approach
            resolvable, targets = self._resolve_jump_table_fast(addr, jumpkind)
            if resolvable:
                all_targets |= set(targets)
                continue

            # is it a slightly more complex jump table? try the slow approach
            # resolvable, targets = self._resolve_jump_table_accurate(addr, jumpkind)
            # if resolvable:
            #    all_targets |= set(targets)
            #    continue

        for t in resolved:
            self._indirect_jumps.remove(t)

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
        b = Blade(self.graph, addr, -1, cfg=self, project=self.project, ignore_sp=True, ignore_bp=True)

        stmt_loc = (addr, 'default')

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
        """
        for addr, stmt_idx in sorted(list(b.slice.nodes())):
            irsb = self.project.factory.block(addr).vex
            stmts = irsb.statements
            print "%x: %d | " % (addr, stmt_idx),
            print "%s" % stmts[stmt_idx],
            print "%d" % b.slice.in_degree((addr, stmt_idx))
        print ""
        """

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
                jump_addr = state.scratch.temps[load_addr_tmp]
                total_cases = jump_addr._model_vsa.cardinality
                all_targets = [ ]

                if total_cases > self._indirect_jump_target_limit:
                    # We resolved too many targets for this indirect jump. Something might have gone wrong.
                    l.warning("%d targets are resolved for the indirect jump at %#x. It may not be a jump table"
                              , total_cases, addr)
                    return False, None

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.se.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr + (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                for idx, a in enumerate(state.se.any_n_int(jump_addr, total_cases)):
                    if idx % 100 == 0:
                        l.debug("Resolved %d targets for the indirect jump at %#x", idx, addr)
                    jump_target = state.memory.load(a, state.arch.bits / 8, endness=state.arch.memory_endness)
                    target = state.se.any_int(jump_target)
                    all_targets.append(target)
                    jump_table.append(target)

                l.info("Jump table resolution: resolved %d targets from %#x", len(all_targets), addr)
                self._jump_tables[addr] = jump_table
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
                    l.warning("%d targets are resolved for the indirect jump at %#x. It may not be a jump table"
                              , addr)
                    return False, None

                    # Or alternatively, we can ask user, which is meh...
                    #
                    # jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                    # total_cases = int(raw_input("please give me the total cases: "))
                    # jump_target = state.se.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr + (total_cases - 1) * 8, stride=8)

                jump_table = [ ]

                for idx, target in enumerate(state.se.any_n_int(jump_target, total_cases)):
                    if idx % 100 == 0:
                        l.debug("Resolved %d targets for the indirect jump at %#x", idx, addr)
                    all_targets.append(target)
                    jump_table.append(target)

                    l.info("Jump table resolution: resolved %d targets from %#x", len(all_targets), addr)
                    self._jump_tables[addr] = jump_table
                    return True, all_targets

    def _resolve_indirect_calls(self):
        """

        :return:
        """

        # TODO: Fix and enable this method later

        function_starts = set()

        for jumpkind, irsb_addr in self._indirect_jumps:
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

    def _remove_overlapping_blocks(self):
        """
        On X86 and AMD64 there are sometimes garbage bytes (usually nops) between functions in order to properly
        align the succeeding function. CFGFast does a linear sweeping which might create duplicated blocks for
        function epilogues where one block starts before the garbage bytes and the other starts after the garbage bytes.

        This method enumerates all blocks and remove overlapping blocks if one of them is aligned to 0x10 and the other
        contains only garbage bytes.

        :return: None
        """

        sorted_nodes = sorted(self.graph.nodes(), key=lambda n: n.addr if n is not None else 0)

        for i in xrange(len(sorted_nodes) - 1):
            a, b = sorted_nodes[i], sorted_nodes[i + 1]

            if a is None or b is None:
                continue

            if a.addr <= b.addr and \
                    (a.addr + a.size > b.addr):
                # They are overlapping
                if b.addr in self.kb.functions and (b.addr - a.addr < 0x10) and b.addr % 0x10 == 0:
                    # b is the beginning of a function
                    # a should be removed
                    self._remove_node(a)

                else:
                    try:
                        block = self.project.factory.block(a.addr, max_size=b.addr-a.addr)
                    except AngrTranslationError:
                        continue
                    if len(block.capstone.insns) == 1 and block.capstone.insns[0].insn_name() == "nop":
                        # It's a big nop
                        self._remove_node(a)

    def _remove_node(self, node):
        """
        Remove a CFGNode from self.graph as well as from the function manager (if it is the beginning of a function)

        :param CFGNode node: The CFGNode to remove from the graph.
        :return: None
        """

        self.graph.remove_node(node)

        # We wanna remove the function as well
        if node.addr in self.kb.functions:
            del self.kb.functions[node.addr]

        if node.addr in self.kb.functions.callgraph:
            self.kb.functions.callgraph.remove_node(node.addr)

    def _analyze(self):
        """
        Perform a full code scan on the target binary, and try to identify as much code as possible.
        In order to identify as many functions as possible, and as accurate as possible, the following operation
        sequence is followed:

        # Active scanning
        - If the binary has "function symbols" (TODO: this term is not accurate enough), they are starting points of
            the code scanning
        - If the binary does not have any "function symbol", we will first perform a function prologue scanning on the
            entire binary, and start from those places that look like function beginnings
        - Otherwise, the binary's entry point will be the starting point for scanning

        # Passive scanning
        - After all active scans are done, we will go through the whole image and scan all code pieces
        """

        # We gotta time this function
        start_time = datetime.now()

        traced_address = set()

        self._graph = networkx.DiGraph()

        # Create an initial state. Store it to self so we can use it globally.
        self._initial_state = self.project.factory.blank_state(mode="fastpath")
        initial_options = self._initial_state.options - {simuvex.o.TRACK_CONSTRAINTS} - simuvex.o.refs
        initial_options |= {simuvex.o.SUPER_FASTPATH}
        # initial_options.remove(simuvex.o.COW_STATES)
        self._initial_state.options = initial_options
        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        function_exits = defaultdict(set)

        if self._show_progressbar:
            self._initialize_progressbar()

        starting_points = set()

        rebase_addr = self._binary.rebase_addr

        if self._use_symbols:
            starting_points |= set([ addr + rebase_addr for addr in self._func_addrs_from_symbols() ])

        if self._use_function_prologues:
            starting_points |= set([ addr + rebase_addr for addr in self._func_addrs_from_prologues() ])

        if not self._force_complete_scan:
            starting_points.add(self._start)

        # Sort it
        starting_points = sorted(list(starting_points), reverse=True)

        while True:
            maybe_function = False
            next_addr = None
            if starting_points:
                next_addr = starting_points.pop()
                maybe_function = True

                if self._seg_list.is_occupied(next_addr):
                    continue

            if not next_addr:
                # Try to see if there is any indirect jump left to be resolved
                if self._resolve_indirect_jumps and self._indirect_jumps:
                    starting_points += list(set(self._process_indirect_jumps()))
                    continue

            if not next_addr and self._force_complete_scan:
                next_addr = self._next_code_addr()

            if self._show_progressbar or self._progress_callback:
                percentage = self._seg_list.occupied_size * 100.0 / self._exec_mem_region_size
                if percentage > 100.0:
                    percentage = 100.0

                if self._show_progressbar:
                    self._update_progressbar(percentage)

                if self._progress_callback:
                    self._progress_callback(percentage)

            if next_addr is None:
                l.info('No more addr to analyze.')
                break

            self._scan_code(traced_address, function_exits, next_addr, maybe_function)

        if self._show_progressbar:
            self._finish_progressbar()

        self._remove_overlapping_blocks()

        end_time = datetime.now()
        l.info("Generating CFGFast takes %d seconds.", (end_time - start_time).seconds)

    #
    # Public methods
    #

    def generate_code_cover(self):
        """
        Generate a list of all recovered basic blocks.
        """

        # TODO: Reimplement this method

        lst = []
        for irsb_addr in self.graph.nodes():
            if irsb_addr not in self._block_size:
                continue
            irsb_size = self._block_size[irsb_addr]
            lst.append((irsb_addr, irsb_size))

        lst = sorted(lst, key=lambda x: x[0])
        return lst

register_analysis(CFGFast, 'CFGFast')

from .cfg_node import CFGNode
from ..blade import Blade
from ..errors import AngrTranslationError, AngrMemoryError
