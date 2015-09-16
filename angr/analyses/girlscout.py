import logging
import string
import math
import re
import os
import pickle
from datetime import datetime
from collections import defaultdict

import networkx
import progressbar

import simuvex
import cle
import pyvex

from ..errors import AngrError
from ..analysis import Analysis, register_analysis
from ..surveyors import Explorer, Slicecutor
from ..annocfg import AnnotatedCFG

l = logging.getLogger("angr.analyses.girlscout")

class SegmentList(object):
    def __init__(self):
        self._list = []
        self._bytes_occupied = 0

    def _search(self, addr):
        start = 0
        end = len(self._list)
        mid = 0
        while start != end:
            mid = (start + end) / 2
            # print ">start = %d, end = %d, mid = %d" % (start, end, mid)
            tpl = self._list[mid]
            if addr < tpl[0]:
                end = mid
            elif addr >= tpl[1]:
                start = mid + 1
            else:
                # Overlapped :(
                start = mid
                break
            # print "<start = %d, end = %d, mid = %d" % (start, end, mid)
        return start

    def _merge_check(self, address, size, idx):
        # Shall we merge it with the one in front?
        merged = False
        new_start = address
        new_end = address + size
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

    def has_blocks(self):
        return len(self._list) > 0

    def next_free_pos(self, address):
        idx = self._search(address + 1)
        if idx < len(self._list) and \
                address >= self._list[idx][0] and address < self._list[idx][1]:
            # Occupied
            i = idx
            while i + 1 < len(self._list) and \
                    self._list[i][1] == self._list[i + 1][0]:
                i += 1
            if i == len(self._list):
                return self._list[-1][1]
            else:
                return self._list[i][1]
        else:
            return address + 1

    def is_occupied(self, address):
        idx = self._search(address)
        if address >= self._list[idx][0] and address <= self._list[idx][1]:
            return True
        if idx > 0 and \
                address <= self._list[idx - 1][1]:
            return True
        return False

    def occupy(self, address, size):
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

    @property
    def occupied_size(self):
        return self._bytes_occupied

    def _dbg_output(self):
        s = "["
        lst = []
        for start, end in self._list:
            lst.append("(0x%08x, 0x%08x)" % (start, end))
        s += ", ".join(lst)
        s += "]"
        return s

    def _debug_check(self):
        old_start = 0
        old_end = 0
        for start, end in self._list:
            if start <= old_end:
                raise Exception("Error in SegmentList: blocks are not merged")
            old_start = start
            old_end = end

class GirlScout(Analysis):
    '''
    We find functions inside the given binary, try to decide the base address if needed, and build a control-flow
    graph on top of that to see if there is an entry or not. Obviously if the binary is not loaded as a blob (not
    using Blob as its backend), GirlScout will not try to determine the base address.

    It's also optional to perform a full code scan of the binary to show where all codes are. By default we don't scan
    the entire binary since it's time consuming.

    You probably need a BoyScout to determine the possible architecture and endianess of your binary blob.
    '''

    def __init__(self, binary=None, start=None, end=None, pickle_intermediate_results=False, perform_full_code_scan=False):
        self._binary = binary if binary is not None else self.project.loader.main_bin
        self._start = start if start is not None else (self._binary.rebase_addr + self._binary.get_min_addr())
        self._end = end if end is not None else (self._binary.rebase_addr + self._binary.get_max_addr())
        self._pickle_intermediate_results = pickle_intermediate_results
        self._perform_full_code_scan = perform_full_code_scan

        l.debug("Starts at 0x%08x and ends at 0x%08x.", self._start, self._end)

        # Valid memory regions
        self._valid_memory_regions = sorted(
            [ (self._binary.rebase_addr+start, self._binary.rebase_addr+start+len(cbacker))
                for start, cbacker in self.project.loader.memory.cbackers ],
            key=lambda x: x[0]
        )
        self._valid_memory_region_size = sum([ (end - start) for start, end in self._valid_memory_regions ])

        # Size of each basic block
        self._block_size = { }

        self._next_addr = self._start - 1
        # Starting point of functions
        self.functions = None
        # Calls between functions
        self.call_map = networkx.DiGraph()
        # A CFG - this is not what you get from project.analyses.CFG() !
        self.cfg = networkx.DiGraph()
        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

        # All IRSBs with an indirect exit target
        self._indirect_jumps = set()

        self._unassured_functions = set()

        self.base_address = None

        # Start working!
        self._reconnoiter()

    @property
    def call_map(self):
        return self.call_map

    def _get_next_addr_to_search(self, alignment=None):
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
                # accept, but we are skipping the gap
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

    def _get_next_code_addr(self, initial_state):
        '''
        Besides calling _get_next_addr, we will check if data locates at that
        address seems to be code or not. If not, we'll move on to request for
        next valid address.
        '''
        next_addr = self._get_next_addr_to_search()
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
                        else:
                            reach_end = True
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
                next_addr = self._get_next_addr_to_search()
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

        l.debug('_get_next_code_addr() returns 0x%x', start_addr)
        return start_addr

    def _symbolic_reconnoiter(self, addr, target_addr, max_depth=10):
        '''
        When an IRSB has more than two exits (for example, a jumptable), we
        cannot concretize their exits in concrete mode. Hence we statically
        execute the function from beginning in this method, and then switch to
        symbolic mode for the final IRSB to get all possible exits of that
        IRSB.
        '''
        state = self.project.factory.blank_state(addr=addr,
                                                  mode="symbolic",
                                                  add_options={simuvex.o.CALLLESS}
                                                 )
        initial_exit = self.project.factory.path(state)
        explorer = Explorer(self.project,
                            start=initial_exit,
                            max_depth=max_depth,
                            find=(target_addr), num_find=1).run()
        if len(explorer.found) > 0:
            path = explorer.found[0]
            last_run = path.last_run
            return last_run.flat_exits()
        else:
            return []

    def _static_memory_slice(self, run):
        if isinstance(run, simuvex.SimIRSB):
            for stmt in run.statements:
                refs = stmt.actions
                if len(refs) > 0:
                    real_ref = refs[-1]
                    if type(real_ref) == simuvex.SimActionData:
                        if real_ref.action == 'write':
                            addr = real_ref.addr
                            if not run.initial_state.se.symbolic(addr):
                                concrete_addr = run.initial_state.se.any_int(addr)
                                self._write_addr_to_run[addr].append(run.addr)
                        elif real_ref.action == 'read':
                            addr = real_ref.addr
                            if not run.initial_state.se.symbolic(addr):
                                concrete_addr = run.initial_state.se.any_int(addr)
                            self._read_addr_to_run[addr].append(run.addr)

    def _scan_code(self, traced_addresses, function_exits, initial_state, starting_address):
        # Saving tuples like (current_function_addr, next_exit_addr)
        # Current_function_addr == -1 for exits not inside any function
        remaining_exits = set()
        next_addr = starting_address

        # Initialize the remaining_exits set
        remaining_exits.add((next_addr,
                             next_addr,
                             next_addr,
                             initial_state.copy()))

        while len(remaining_exits):
            current_function_addr, previous_addr, parent_addr, state = \
                remaining_exits.pop()
            if previous_addr in traced_addresses:
                continue

            # Add this node to the CFG first, in case this is a dangling node
            self.cfg.add_node(previous_addr)

            if current_function_addr != -1:
                l.debug("Tracing new exit 0x%08x in function 0x%08x",
                        previous_addr, current_function_addr)
            else:
                l.debug("Tracing new exit 0x%08x", previous_addr)
            traced_addresses.add(previous_addr)

            self._scan_block(previous_addr, state, current_function_addr, function_exits, remaining_exits, traced_addresses)


    def _scan_block(self, addr, state, current_function_addr, function_exits, remaining_exits, traced_addresses):
        # Let's try to create the pyvex IRSB directly, since it's much faster

        try:
            irsb = self.project.factory.block(addr).vex

            # Log the size of this basic block
            self._block_size[addr] = irsb.size

            # Occupy the block
            self._seg_list.occupy(addr, irsb.size)
        except (AngrTranslationError, AngrMemoryError):
            return

        # Get all possible successors
        next, jumpkind = irsb.next, irsb.jumpkind
        successors = [ (i.dst, i.jumpkind) for i in irsb.statements if type(i) is pyvex.IRStmt.Exit]
        successors.append((next, jumpkind))

        # Process each successor
        for suc in successors:
            target, jumpkind = suc

            if type(target) is pyvex.IRExpr.Const:
                next_addr = target.con.value
            else:
                next_addr = None

            if jumpkind == 'Ijk_Boring' and next_addr is not None:
                remaining_exits.add((current_function_addr, next_addr,
                                     addr, None))

            elif jumpkind == 'Ijk_Call' and next_addr is not None:
                # Log it before we cut the tracing :)
                if jumpkind == "Ijk_Call":
                    if current_function_addr != -1:
                        self.functions.add(current_function_addr)
                        self.functions.add(next_addr)
                        self.call_map.add_edge(current_function_addr, next_addr)
                    else:
                        self.functions.add(next_addr)
                        self.call_map.add_node(next_addr)
                elif jumpkind == "Ijk_Boring" or \
                                jumpkind == "Ijk_Ret":
                    if current_function_addr != -1:
                        function_exits[current_function_addr].add(next_addr)

                # If we have traced it before, don't trace it anymore
                if next_addr in traced_addresses:
                    return

                remaining_exits.add((next_addr, next_addr, addr, None))
                l.debug("Function calls: %d", len(self.call_map.nodes()))

    def _scan_block_(self, addr, state, current_function_addr, function_exits, remaining_exits, traced_addresses):

        # Get a basic block
        state.ip = addr

        s_path = self.project.factory.path(state)
        try:
            s_run = s_path.next_run
        except simuvex.SimIRSBError, ex:
            l.debug(ex)
            return
        except AngrError, ex:
            # "No memory at xxx"
            l.debug(ex)
            return
        except (simuvex.SimValueError, simuvex.SimSolverModeError), ex:
            # Cannot concretize something when executing the SimRun
            l.debug(ex)
            return
        except simuvex.SimError as ex:
            # Catch all simuvex errors
            l.debug(ex)
            return

        if type(s_run) is simuvex.SimIRSB:
            # Calculate its entropy to avoid jumping into uninitialized/all-zero space
            bytes = s_run.irsb._state[1]['bytes']
            size = s_run.irsb.size
            ent = self._calc_entropy(bytes, size=size)
            if ent < 1.0 and size > 40:
                # Skipping basic blocks that have a very low entropy
                return

        # self._static_memory_slice(s_run)

        # Mark that part as occupied
        if isinstance(s_run, simuvex.SimIRSB):
            self._seg_list.occupy(addr, s_run.irsb.size)
        successors = s_run.flat_successors + s_run.unsat_successors
        has_call_exit = False
        tmp_exit_set = set()
        for suc in successors:
            if suc.scratch.jumpkind == "Ijk_Call":
                has_call_exit = True

        for suc in successors:
            jumpkind = suc.scratch.jumpkind

            if has_call_exit and jumpkind == "Ijk_Ret":
                jumpkind = "Ijk_FakeRet"

            if jumpkind == "Ijk_Ret":
                continue

            try:
                # Try to concretize the target. If we can't, just move on
                # to the next target
                next_addr = suc.se.exactly_n_int(suc.ip, 1)[0]
            except (simuvex.SimValueError, simuvex.SimSolverModeError) as ex:
                # Undecidable jumps (might be a function return, or a conditional branch, etc.)

                # We log it
                self._indirect_jumps.add((suc.scratch.jumpkind, addr))
                l.info("IRSB 0x%x has an indirect exit %s.", addr, suc.scratch.jumpkind)

                continue

            self.cfg.add_edge(addr, next_addr, jumpkind=jumpkind)
            # Log it before we cut the tracing :)
            if jumpkind == "Ijk_Call":
                if current_function_addr != -1:
                    self.call_map.add_edge(current_function_addr, next_addr)
                else:
                    self.call_map.add_node(next_addr)
            elif jumpkind == "Ijk_Boring" or \
                            jumpkind == "Ijk_Ret":
                if current_function_addr != -1:
                    function_exits[current_function_addr].add(next_addr)

            # If we have traced it before, don't trace it anymore
            if next_addr in traced_addresses:
                continue
            # If we have traced it in current loop, don't tract it either
            if next_addr in tmp_exit_set:
                continue

            tmp_exit_set.add(next_addr)

            if jumpkind == "Ijk_Call":
                # This is a call. Let's record it
                new_state = suc.copy()
                # Unconstrain those parameters
                # TODO: Support other archs as well
                # if 12 + 16 in new_state.registers.mem:
                #    del new_state.registers.mem[12 + 16]
                #if 16 + 16 in new_state.registers.mem:
                #    del new_state.registers.mem[16 + 16]
                #if 20 + 16 in new_state.registers.mem:
                #    del new_state.registers.mem[20 + 16]
                # 0x8000000: call 0x8000045
                remaining_exits.add((next_addr, next_addr, addr, new_state))
                l.debug("Function calls: %d", len(self.call_map.nodes()))
            elif jumpkind == "Ijk_Boring" or \
                            jumpkind == "Ijk_Ret" or \
                            jumpkind == "Ijk_FakeRet":
                new_state = suc.copy()
                l.debug("New exit with jumpkind %s", jumpkind)
                # FIXME: should not use current_function_addr if jumpkind is "Ijk_Ret"
                remaining_exits.add((current_function_addr, next_addr,
                                     addr, new_state))
            elif jumpkind == "Ijk_NoDecode":
                # That's something VEX cannot decode!
                # We assume we ran into a deadend
                pass
            elif jumpkind.startswith("Ijk_Sig"):
                # Should not go into that exit
                pass
            elif jumpkind == "Ijk_TInval":
                # ppc32: isync
                # FIXME: It is the same as Ijk_Boring! Process it later
                pass
            elif jumpkind == 'Ijk_Sys_syscall':
                # Let's not jump into syscalls
                pass
            elif jumpkind == 'Ijk_InvalICache':
                pass
            elif jumpkind == 'Ijk_MapFail':
                pass
            elif jumpkind == 'Ijk_EmWarn':
                pass
            else:
                raise Exception("NotImplemented")

    def _scan_function_prologues(self, traced_address, function_exits, initial_state):
        '''
        Scan the entire program space for prologues, and start code scanning at those positions
        :param traced_address:
        :param function_exits:
        :param initial_state:
        :param next_addr:
        :return:
        '''

        # Precompile all regexes
        regexes = set()
        for ins_regex in self.project.arch.function_prologs:
            r = re.compile(ins_regex)
            regexes.add(r)

        # TODO: Make sure self._start is aligned

        # Construct the binary blob first
        # TODO: We shouldn't directly access the _memory of main_bin. An interface
        # to that would be awesome.

        strides = self.project.loader.main_bin.memory.stride_repr

        for start_, end_, bytes in strides:
            for regex in regexes:
                # Match them!
                for mo in regex.finditer(bytes):
                    position = mo.start() + start_
                    if position % self.project.arch.instruction_alignment == 0:
                        if position not in traced_address:
                            percentage = self._seg_list.occupied_size * 100.0 / (self._valid_memory_region_size)
                            l.info("Scanning %xh, progress %0.04f%%", position, percentage)

                            self._unassured_functions.add(position)

                            self._scan_code(traced_address, function_exits, initial_state, position)
                        else:
                            l.info("Skipping %xh", position)

    def _process_indirect_jumps(self):
        '''
        Execute each basic block with an indeterminiable exit target
        :return:
        '''

        function_starts = set()
        print "We have %d indirect jumps" % len(self._indirect_jumps)

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
                except simuvex.SimSolverModeError as ex:
                    pass

                # Not resolved
                # Do a backward slicing from the call
                irsb = self.project.factory.block(irsb_addr).vex
                stmts = irsb.statements
                # Start slicing from the "next"

                b = Blade(self.cfg, irsb.addr, -1, project=self.project)

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
                annotatedcfg = AnnotatedCFG(self.project, None, target_irsb_addr=irsb_addr, detect_loops=False)
                annotatedcfg.from_digraph(b.slice)

                for src_irsb, src_stmt_idx in sources:
                    # Use slicecutor to execute each one, and get the address
                    # We simply give up if any exception occurs on the way

                    start_state = self.project.factory.blank_state(addr=src_irsb,
                                                              add_options=
                                                              {simuvex.o.DO_RET_EMULATION,
                                                               simuvex.o.TRUE_RET_EMULATION_GUARD}
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

    def _solve_forbase_address(self, function_starts, functions):
        '''
        Voting for the most possible base address.

        :param function_starts:
        :param functions:
        :return:
        '''

        pseudo_base_addr = self.project.loader.main_bin.get_min_addr()

        base_addr_ctr = { }

        for s in function_starts:
            for f in functions:
                base_addr = s - f + pseudo_base_addr
                ctr = 1

                for k in function_starts:
                    if k - base_addr + pseudo_base_addr in functions:
                        ctr += 1

                if ctr > 5:
                    base_addr_ctr[base_addr] = ctr

        if len(base_addr_ctr):
            base_addr, hits = sorted([(k, v) for k, v in base_addr_ctr.iteritems()], key=lambda x: x[1], reverse=True)[0]

            return base_addr
        else:
            return None


    def _reconnoiter(self):

        if type(self._binary) is cle.blob.Blob:
            self._determinebase_address()

        if self._perform_full_code_scan:
            self._full_code_scan()

    def _determinebase_address(self):
        '''
        The basic idea is simple: start from a specific point, try to construct
        functions as much as we can, and maintain a function distribution graph
        and a call graph simultaneously. Repeat searching until we come to the
        end that there is no new function to be found.
        A function should start with:
            # some addresses that a call exit leads to, or
            # certain instructions. They are recoreded in SimArch.

        For a better performance, instead of blindly scanning the entire process
        space, we first try to search for instruction patterns that a function
        may start with, and start scanning at those positions. Then we try to
        decode anything that is left.
        '''

        traced_address = set()
        self.functions = set()
        self.call_map = networkx.DiGraph()
        self.cfg = networkx.DiGraph()
        initial_state = self.project.factory.blank_state(mode="fastpath")
        initial_options = initial_state.options - { simuvex.o.TRACK_CONSTRAINTS } - simuvex.o.refs
        initial_options |= { simuvex.o.SUPER_FASTPATH }
        # initial_options.remove(simuvex.o.COW_STATES)
        initial_state.options = initial_options
        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        function_exits = defaultdict(set)

        dump_file_prefix = self.project.filename

        if self._pickle_intermediate_results and \
                os.path.exists(dump_file_prefix + "_indirect_jumps.angr"):
            l.debug("Loading existing intermediate results.")
            self._indirect_jumps = pickle.load(open(dump_file_prefix + "_indirect_jumps.angr", "rb"))
            self.cfg = pickle.load(open(dump_file_prefix + "_coercecfg.angr", "rb"))
            self._unassured_functions = pickle.load(open(dump_file_prefix + "_unassured_functions.angr", "rb"))
        else:
            # Performance boost :-)
            # Scan for existing function prologues
            self._scan_function_prologues(traced_address, function_exits, initial_state)

            if self._pickle_intermediate_results:
                l.debug("Dumping intermediate results.")
                pickle.dump(self._indirect_jumps, open(dump_file_prefix + "_indirect_jumps.angr", "wb"))
                pickle.dump(self.cfg, open(dump_file_prefix + "_coercecfg.angr", "wb"))
                pickle.dump(self._unassured_functions, open(dump_file_prefix + "_unassured_functions.angr", "wb"))

        if len(self._indirect_jumps):
            # We got some indirect jumps!
            # Gotta execute each basic block and see where it wants to jump to
            function_starts = self._process_indirect_jumps()

            self.base_address = self._solve_forbase_address(function_starts, self._unassured_functions)

            l.info("Base address should be 0x%x", self.base_address)

        else:
            l.debug("No indirect jumps are found. We switch to the slowpath mode.")
            # TODO: Slowpath mode...
            while True:
                next_addr = self._get_next_code_addr(initial_state)
                percentage = self._seg_list.occupied_size * 100.0 / (self._valid_memory_region_size)
                l.info("Analyzing %xh, progress %0.04f%%", next_addr, percentage)
                if next_addr is None:
                    break

                self.call_map.add_node(next_addr)

                self._scan_code(traced_address, function_exits, initial_state, next_addr)

        # Post-processing: Map those calls that are not made by call/blr
        # instructions to their targets in our map
        for src, s in function_exits.items():
            if src in self.call_map:
                for target in s:
                    if target in self.call_map:
                        self.call_map.add_edge(src, target)

        nodes = sorted(self.call_map.nodes())
        for i in range(len(nodes) - 1):
            if nodes[i] >= nodes[i + 1] - 4:
                for dst in self.call_map.successors(nodes[i + 1]):
                    self.call_map.add_edge(nodes[i], dst)
                for src in self.call_map.predecessors(nodes[i + 1]):
                    self.call_map.add_edge(src, nodes[i])
                self.call_map.remove_node(nodes[i + 1])

        l.debug("Construction finished.")

    def _full_code_scan(self):
        """
        Perform a full code scan on the target binary.
        """

        # We gotta time this function
        start_time = datetime.now()

        traced_address = set()
        self.functions = set()
        self.call_map = networkx.DiGraph()
        self.cfg = networkx.DiGraph()
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

        while True:
            next_addr = self._get_next_code_addr(initial_state)
            percentage = self._seg_list.occupied_size * 100.0 / (self._valid_memory_region_size)
            if percentage > 100.0: percentage = 100.0
            pb.update(percentage * 10000)

            if next_addr is not None:
                l.info("Analyzing %xh, progress %0.04f%%", next_addr, percentage)
            else:
                l.info('No more addr to analyze. Progress %0.04f%%', percentage)
                break

            self.call_map.add_node(next_addr)

            self._scan_code(traced_address, function_exits, initial_state, next_addr)

        pb.finish()
        end_time = datetime.now()
        l.info("A full code scan takes %d seconds.", (end_time - start_time).seconds)

    def _calc_entropy(self, data, size=None):
        if not data:
            return 0
        entropy = 0
        if size is None: size = len(data)
        data = str(pyvex.ffi.buffer(data, size))
        for x in xrange(0, 256):
            p_x = float(data.count(chr(x)))/size
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def _dbg_output(self):
        ret = ""
        ret += "Functions:\n"
        function_list = list(self.functions)
        # Sort it
        function_list = sorted(function_list)
        for f in function_list:
            ret += "0x%08x" % f

        return ret

    def genenare_callmap_sif(self, filepath):
        """
        Generate a sif file from the call map
        """
        graph = self.call_map

        if graph is None:
            raise AngrGirlScoutError('Please generate the call graph first.')

        f = open(filepath, "wb")

        for src, dst in graph.edges():
            f.write("0x%x\tDirectEdge\t0x%x\n" % (src, dst))

        f.close()

    def generate_code_cover(self):
        """
        Generate a list of all recovered basic blocks.
        """

        lst = [ ]
        for irsb_addr in self.cfg.nodes():
            if irsb_addr not in self._block_size:
                continue
            irsb_size = self._block_size[irsb_addr]
            lst.append((irsb_addr, irsb_size))

        lst = sorted(lst, key=lambda x: x[0])

        return lst

register_analysis(GirlScout, 'GirlScout')

from ..blade import Blade
from ..errors import AngrGirlScoutError, AngrTranslationError, AngrMemoryError
