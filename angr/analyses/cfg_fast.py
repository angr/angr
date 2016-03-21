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
import cle

from ..analysis import Analysis, register_analysis
from ..surveyors import Slicecutor
from ..annocfg import AnnotatedCFG
from .cfg_base import CFGBase

l = logging.getLogger("angr.analyses.cfg_fast")


class SegmentList(object):
    """
    SegmentList describes a series of segmented memory blocks. You may query whether an address belongs to any of the
    blocks or not, and obtain the exact block(segment) that the address belongs to.
    """

    def __init__(self):
        self._list = []
        self._bytes_occupied = 0

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

            tpl = self._list[mid]
            if addr < tpl[0]:
                end = mid
            elif addr >= tpl[1]:
                start = mid + 1
            else:
                # Overlapped :(
                start = mid
                break

        return start

    def _merge_check(self, address, size, idx):
        """
        Determines whether the block specified by (address, size) should be merged with the block in front of it.

        :param address: Starting address of the block to be merged
        :param size: Size of the block to be merged
        :param idx: ID of the address
        :return: None
        """

        # Shall we merge it with the one in front?
        merged = False
        new_start = address
        new_idx = idx

        while new_idx > 0:
            new_idx -= 1
            tpl = self._list[new_idx]
            if new_start <= tpl[1]:
                del self._list[new_idx]
                new_start = min(tpl[0], address)
                new_end = max(tpl[1], address + size)
                self._list.insert(new_idx,
                                  (new_start, new_end))
                self._bytes_occupied += (new_end - new_start) - (tpl[1] - tpl[0])
                merged = True
            else:
                break

        if not merged:
            if idx == len(self._list):
                self._list.append((address, address + size))
            else:
                self._list.insert(idx, (address, address + size))
            self._bytes_occupied += size

    def _dbg_output(self):
        s = "["
        lst = []
        for start, end in self._list:
            lst.append("(0x%08x, 0x%08x)" % (start, end))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
        # old_start = 0
        old_end = 0
        for start, end in self._list:
            if start <= old_end:
                raise Exception("Error in SegmentList: blocks are not merged")
            # old_start = start
            old_end = end

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
        if idx < len(self._list) and self._list[idx][0] <= address < self._list[idx][1]:
            # Occupied
            i = idx
            while i + 1 < len(self._list) and self._list[i][1] == self._list[i + 1][0]:
                i += 1
            if i == len(self._list):
                return self._list[-1][1]
            else:
                return self._list[i][1]
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
        if address >= self._list[idx][0] and address <= self._list[idx][1]:
            return True
        if idx > 0 and address < self._list[idx - 1][1]:
            return True
        return False

    def occupy(self, address, size):
        """
        Include a block, specified by (address, size), in this segment list.

        :param address: The starting address of the block
        :param size: Size of the block
        :return: None
        """

        # l.debug("Occpuying 0x%08x-0x%08x", address, address + size)
        if len(self._list) == 0:
            self._list.append((address, address + size))
            self._bytes_occupied += size
            return
        # Find adjacent element in our list
        idx = self._search(address)
        # print idx
        if idx == len(self._list):
            # We should append at the end
            self._merge_check(address, size, idx)
        else:
            tpl = self._list[idx]
            # Overlap check
            if address <= tpl[0] and address + size >= tpl[0] or \
                    address <= tpl[1] and address + size >= tpl[1] or \
                    address >= tpl[0] and address + size <= tpl[1]:
                new_start = min(address, tpl[0])
                new_end = max(address + size, tpl[1])
                self._list[idx] = (new_start, new_end)
                # Shall we merge it with the previous one?
                # Remember to remove this one if we shall merge it with the one
                # in front!
                while idx > 0:
                    idx -= 1
                    if new_start <= self._list[idx][1]:
                        new_start = min(self._list[idx][0], new_start)
                        new_end = max(self._list[idx][1], new_end)
                        self._list[idx] = (new_start, new_end)
                        del self._list[idx + 1]
                    else:
                        break
            else:
                # It's not overlapped with this one
                # Shall we merge it with the previous one?
                self._merge_check(address, size, idx)
                # l.debug(self._dbg_output())
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

    def __init__(self, binary=None, start=None, end=None, pickle_intermediate_results=False,
                 symbols=True, function_prologues=True, resolve_indirect_jumps=True, force_segment=False,
                 force_complete_scan=True):
        """
        Constructor

        :param binary:
        :param start:
        :param end:
        :param pickle_intermediate_results:
        :param symbols: Get function beginnings from symbols in the binary.
        :param function_prologues: Scan the binary for function prologues, and use those positions as function
                beginnings
        :param resolve_indirect_jumps: Try to resolve indirect jumps. This is necessary to resolve jump targets from jump
                tables, etc.
        :param force_segment: Force CFGFast to rely on binary segments instead of sections.
        :param bool force_complete_scan: Perform a complete scan on the binary and maximize the number of identified code
                blocks.
        :return: None
        """

        CFGBase.__init__(self, self.project, 0)

        self._binary = binary if binary is not None else self.project.loader.main_bin
        self._start = start if start is not None else (self._binary.rebase_addr + self._binary.get_min_addr())
        self._end = end if end is not None else (self._binary.rebase_addr + self._binary.get_max_addr())

        self._pickle_intermediate_results = pickle_intermediate_results

        self._use_symbols = symbols
        self._use_function_prologues = function_prologues
        self._resolve_indirect_jumps = resolve_indirect_jumps
        self._force_segment = force_segment
        self._force_complete_scan = force_complete_scan

        l.debug("Starts at %#x and ends at %#x.", self._start, self._end)

        # Get all valid memory regions
        self._valid_memory_regions = self._executable_memory_regions()
        self._valid_memory_region_size = sum([(end - start) for start, end in self._valid_memory_regions])

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

    def _executable_memory_regions(self):
        """
        Get all executable memory regions from the binary

        :return: A sorted list of tuples (beginning_address, end_address)
        """

        memory_regions = [ ]
        rebase_addr = self._binary.rebase_addr

        if isinstance(self._binary, cle.ELF):
            # If we have sections, we get result from sections
            if not self._force_segment and self._binary.sections:
                # Get all executable sections
                for section in self._binary.sections:
                    if section.is_executable:
                        tpl = (rebase_addr + section.vaddr, rebase_addr + section.vaddr + section.memsize)
                        memory_regions.append(tpl)

            else:
                # Get all executable segments
                for segment in self._binary.segments:
                    if segment.is_executable:
                        tpl = (rebase_addr + segment.vaddr, rebase_addr + segment.vaddr + segment.memsize)
                        memory_regions.append(tpl)

        elif isinstance(self._binary, cle.PE):
            for section in self._binary.sections:
                if section.is_executable:
                    tpl = (rebase_addr + section.vaddr, rebase_addr + section.vaddr + section.memsize)
                    memory_regions.append(tpl)

        else:
            memory_regions = [
                (self._binary.rebase_addr + start, self._binary.rebase_addr + start + len(cbacker))
                for start, cbacker in self.project.loader.memory.cbackers
                ]

        memory_regions = sorted(memory_regions, key=lambda x: x[0])

        return memory_regions

    def _addr_in_memory_regions(self, addr):
        """
        Check if the rebased address locates inside any of the valid memory regions
        :param addr: A rebased address
        :return: True/False
        """

        for start, end in self._valid_memory_regions:
            if addr < start:
                # The list is ordered!
                break

            if addr >= start and addr < end:
                return True

        return False

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
        for start, end in self._valid_memory_regions:
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

    def _next_code_addr(self, initial_state):
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
            while next_addr in initial_state.memory:
                try:
                    l.debug("Searching address %x", next_addr)
                    val = initial_state.mem_concrete(next_addr, 1)
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
                self._seg_list.occupy(start_addr, len(sz) + 1)
                sz = ""
                next_addr = self._next_unscanned_addr()
                if next_addr is None:
                    return None
                # l.debug("next addr = %x", next_addr)
                start_addr = next_addr

            if is_sz:
                next_addr += 1

        instr_alignment = initial_state.arch.instruction_alignment
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

    def _scan_code(self, traced_addresses, function_exits, initial_state, starting_address, maybe_function): #pylint:disable=unused-argument
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

        # Let's try to create the pyvex IRSB directly, since it's much faster

        try:
            irsb = self.project.factory.block(addr).vex

            # Create a CFG node, and add it to the graph
            cfg_node = CFGNode(addr, irsb.size, self, function_address=current_function_addr)
            if previous_src_node is None:
                self.graph.add_node(cfg_node)
            else:
                self.graph.add_edge(previous_src_node, cfg_node, jumpkind=previous_jumpkind,
                                    stmt_idx=previous_src_stmt_idx)

            # Occupy the block in segment list
            self._seg_list.occupy(addr, irsb.size)

        except (AngrTranslationError, AngrMemoryError):
            return

        # If we have traced it before, don't trace it anymore
        if addr in traced_addresses:
            return
        traced_addresses.add(addr)

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

            # is it a jump table?
            resolvable, targets = self._resolve_jump_table(addr, jumpkind)

            if resolvable:
                all_targets |= set(targets)
            resolved.add((addr, jumpkind))

        for t in resolved:
            self._indirect_jumps.remove(t)

        return all_targets

    def _resolve_jump_table(self, addr, jumpkind):
        """
        Check if the indirect jump is a jump table, and if it is, resolve it and return all possible targets.

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
                    mode='static',
                    add_options={
                        simuvex.o.DO_RET_EMULATION,
                        simuvex.o.TRUE_RET_EMULATION_GUARD
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

                # Manually parse the address... this is weird :-(
                # FIXME: DO NOT MANUALLY PARSE THE ADDRESS IN THE FUTURE
                all_states = r.unconstrained_successor_states + [ s.state for s in r.successors ]
                state = all_states[0]
                irsb = self.project.factory.block(addr).vex
                irsb_next_tmp = irsb.next.tmp
                for stmt in reversed(list(irsb.statements)):
                    if type(stmt) is pyvex.IRStmt.WrTmp and stmt.tmp == irsb_next_tmp:
                        if not type(stmt.data) is pyvex.IRExpr.Load:
                            return False, None
                        if not type(stmt.data.addr) is pyvex.IRExpr.RdTmp:
                            return False, None
                        addr_tmp = stmt.data.addr.tmp
                        jump_addr = state.scratch.temps[addr_tmp]

                        total_cases = jump_addr._model_vsa.cardinality
                        all_targets = [ ]

                        if total_cases > 100000:
                            # this is a very ugly fix
                            to_fix = jump_addr.args[0]
                            new_arg0 = state.se.SI(bits=state.arch.bits, lower_bound=0, upper_bound=to_fix._model_vsa.upper_bound, stride=to_fix._model_vsa.stride)
                            if jump_addr.op == "__add__":
                                jump_addr = new_arg0 + jump_addr.args[1]
                                total_cases = jump_addr._model_vsa.cardinality
                            else:
                                import ipdb; ipdb.set_trace()

                        if total_cases > 100000:
                            """
                            if addr == 0x485a26:
                                jump_base_addr = 0x815410
                                total_cases = 7
                            elif addr == 0x48d902:
                                jump_base_addr, total_cases = 0x815190, 80
                            elif addr == 0x646dca:
                                jump_base_addr, total_cases = 0x814C48, 75
                            else:
                            """
                            __import__('ipdb').set_trace()
                            jump_base_addr = int(raw_input("please give me the jump base addr: "), 16)
                            total_cases = int(raw_input("please give me the total cases: "))

                            jump_addr = state.se.SI(bits=64, lower_bound=jump_base_addr, upper_bound=jump_base_addr + (total_cases - 1) * 8, stride=8)

                        jump_table = [ ]

                        for idx, a in enumerate(state.se.any_n_int(jump_addr, total_cases)):
                            if idx % 100 == 0:
                                print idx
                            jump_target = state.memory.load(a, state.arch.bits / 8, endness=state.arch.memory_endness)
                            target = state.se.any_int(jump_target)
                            all_targets.append(target)
                            jump_table.append(target)

                        l.info("Jump table resolution: resolved %d targets from %#x", len(all_targets), addr)
                        self._jump_tables[addr] = jump_table
                        return True, all_targets

    def _resolve_indirect_calls(self):
        """

        :return:
        """

        # TODO: Fix this method later

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
                    self.graph.remove_node(a)
                else:
                    try:
                        block = self.project.factory.block(a.addr, max_size=b.addr-a.addr)
                    except AngrTranslationError:
                        continue
                    if len(block.capstone.insns) == 1 and block.capstone.insns[0].insn_name() == "nop":
                        # It's a big nop
                        self.graph.remove_node(a)

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

        initial_state = self.project.factory.blank_state(mode="fastpath")
        initial_options = initial_state.options - {simuvex.o.TRACK_CONSTRAINTS} - simuvex.o.refs
        initial_options |= {simuvex.o.SUPER_FASTPATH}
        # initial_options.remove(simuvex.o.COW_STATES)
        initial_state.options = initial_options
        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        function_exits = defaultdict(set)

        widgets = [progressbar.Percentage(),
                   ' ',
                   progressbar.Bar(marker=progressbar.RotatingMarker()),
                   ' ',
                   progressbar.Timer(),
                   ' ',
                   progressbar.ETA()
                   ]

        pb = progressbar.ProgressBar(widgets=widgets, maxval=10000 * 100).start()

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
                next_addr = self._next_code_addr(initial_state)

            percentage = self._seg_list.occupied_size * 100.0 / self._valid_memory_region_size
            if percentage > 100.0:
                percentage = 100.0
            pb.update(percentage * 10000)

            if next_addr is None:
                l.info('No more addr to analyze. Progress %0.04f%%', percentage)
                break

            self._scan_code(traced_address, function_exits, initial_state, next_addr, maybe_function)

        pb.finish()

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
