import logging
import string
from collections import defaultdict

import networkx

import simuvex
from simuvex.s_ref import SimMemRead, SimMemWrite
import angr

l = logging.getLogger("angr.scout")

class SegmentList(object):
    def __init__(self):
        self._list = []

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
                self._list.insert(new_idx, \
                                  (new_start, new_end))
                merged = True
            else:
                break
        if not merged:
            if idx == len(self._list):
                self._list.append((address, address + size))
            else:
                self._list.insert(idx, (address, address + size))

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

class Scout(object):
    '''
    We iteratively find functions inside the given binary, and build a graph on
    top of that to see if there is an entry or not.
    '''
    def __init__(self, project, starting_point, ending_point=None):
        self._project = project
        self._starting_point = starting_point
        self._ending_point = ending_point
        l.debug("Starts at 0x%08x and ends at 0x%08x.", starting_point, ending_point)

        self._next_addr = starting_point
        # Starting point of functions
        self._functions = None
        # Calls between functions
        self._call_map = None
        # Create the segment list
        self._seg_list = SegmentList()

        self._read_addr_to_run = defaultdict(list)
        self._write_addr_to_run = defaultdict(list)

    def _get_next_addr_to_search(self, alignment=None):
        # TODO: Take care of those functions that are already generated
        curr_addr = self._next_addr
        # Determine the size of that IRSB
        # Note: we don't care about SimProcedure at this moment, as we want to
        # get as many functions as possible
        # s_irsb = None
        # while s_irsb is None:
        #     s_ex = self._project.exit_to(addr=curr_addr, \
        #                     state=self._project.initial_state(mode="static"))
        #     try:
        #         s_irsb = self._project.sim_block(s_ex)
        #     except simuvex.s_irsb.SimIRSBError:
        #         # We cannot build functions there
        #         # Move on to next possible position
        #         s_irsb = None
        #         # TODO: Handle strings
        #         curr_addr = \
        #             self._seg_list.next_free_pos(curr_addr)
        if self._seg_list.has_blocks:
            curr_addr = self._seg_list.next_free_pos(curr_addr)

        if alignment is not None:
            if curr_addr % alignment > 0:
                curr_addr = curr_addr - curr_addr % alignment + alignment
        # block_size = s_irsb.irsb.size()
        # self._next_addr = curr_addr + block_size
        self._next_addr = curr_addr
        if self._ending_point is None or curr_addr < self._ending_point:
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

            next_addr += 1

            if len(sz) > 0 and is_sz:
                l.debug("Got a string of %d chars: [%s]", len(sz), sz)
                # l.debug("Occpuy %x - %x", start_addr, start_addr + len(sz) + 1)
                self._seg_list.occupy(start_addr, len(sz) + 1)
                sz = ""
                next_addr = self._get_next_addr_to_search()
                # l.debug("next addr = %x", next_addr)
                start_addr = next_addr
            else:
                self._seg_list.occupy(start_addr, next_addr - start_addr)

        # Let's search for function prologs
        instr_alignment = initial_state.arch.instruction_alignment
        if start_addr % instr_alignment > 0:
            start_addr = start_addr - start_addr % instr_alignment + \
                instr_alignment

        while True:
            #try:
            #    import ipdb; ipdb.set_trace()
            #    s = initial_state.se.any_str(initial_state.mem_expr(start_addr, 4))
            #except simuvex.SimValueError:
            #    # Memory doesn't exist
            #    return None
            #if s.startswith(initial_state.arch.function_prologs):
            #    break
            start_addr = self._get_next_addr_to_search(alignment=instr_alignment)
            break

        return start_addr

    def _symbolic_reconnoiter(self, addr, target_addr, max_depth=10):
        '''
        When an IRSB has more than two exits (for example, a jumptable), we
        cannot concretize their exits in concrete mode. Hence we statically
        execute the function from beginning in this method, and then switch to
        symbolic mode for the final IRSB to get all possible exits of that
        IRSB.
        '''
        state = self._project.initial_state(mode="symbolic")
        state.options.add(simuvex.o.CALLLESS)
        initial_exit = self._project.exit_to(addr=addr, state=state)
        explorer = angr.surveyors.Explorer(self._project, \
                                           start=initial_exit, \
                                           max_depth=max_depth, \
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
                refs = stmt.refs
                if len(refs) > 0:
                    real_ref = refs[-1]
                    if type(real_ref) == SimMemWrite:
                        addr = real_ref.addr
                        if not run.initial_state.se.symbolic(addr):
                            concrete_addr = run.initial_state.se.any_int(addr)
                            self._write_addr_to_run[addr].append(run.addr)
                    elif type(real_ref) == SimMemRead:
                        addr = real_ref.addr
                        if not run.initial_state.se.symbolic(addr):
                            concrete_addr = run.initial_state.se.any_int(addr)
                        self._read_addr_to_run[addr].append(run.addr)

    def reconnoiter(self):
        '''
        The basic idea is simple: start from a specific point, try to construct
        functions as much as we can, and maintain a function distribution graph
        and a call graph simultaneously. Repeat searching until we come to the
        end that there is no new function to be found.
        A function should start by:
            # some addresses that a call exit leads to, or
            # stack pointer operations (needs elaboration)
        A function should end by:
            # A retn call, or several retn calls
            # Some unsupported instructions (maybe they don't make any sense at
              all)
        TODO:
            # Support dangling functions/code pieces
        '''

        # Saving tuples like (current_function_addr, next_exit_addr)
        # Current_function_addr == -1 for exits not inside any function
        remaining_exits = set()
        traced_address = set()
        self._functions = set()
        self._call_map = networkx.DiGraph()
        initial_state = self._project.initial_state(mode="fastpath")
        initial_options = initial_state.options
        # initial_options.remove(simuvex.o.COW_STATES)
        initial_state.options = initial_options
        # Sadly, not all calls to functions are explicitly made by call
        # instruction - they could be a jmp or b, or something else. So we
        # should record all exits from a single function, and then add
        # necessary calling edges in our call map during the post-processing
        # phase.
        function_exits = defaultdict(set)
        while True:
            if len(remaining_exits) == 0:
                # Load a possible position
                next_addr = self._get_next_code_addr(initial_state)
                if next_addr is None:
                    break
                remaining_exits.add((next_addr, \
                                     next_addr, \
                                     next_addr, \
                                     initial_state.copy()))
                self._call_map.add_node(next_addr)

            current_function_addr, exit_addr, parent_addr, state = \
                remaining_exits.pop()
            if exit_addr in traced_address:
                continue
            if current_function_addr != -1:
                l.debug("Tracing new exit 0x%08x in function 0x%08x", \
                        exit_addr, current_function_addr)
            else:
                l.debug("Tracing new exit 0x%08x", exit_addr)
            traced_address.add(exit_addr)
            # Get a basic block
            s_ex = self._project.exit_to(addr=exit_addr, state=state)
            try:
                s_run = self._project.sim_run(s_ex)
            except simuvex.s_irsb.SimIRSBError:
                continue
            except angr.errors.AngrError:
                # "No memory at xxx"
                continue
            except simuvex.SimValueError:
                # Cannot concretize something when executing the SimRun
                continue

            self._static_memory_slice(s_run)

            # Mark that part as occupied
            if isinstance(s_run, simuvex.SimIRSB):
                self._seg_list.occupy(exit_addr, s_run.irsb.size())
            new_exits = s_run.exits()
            has_call_exit = False
            tmp_exit_set = set()
            for new_exit in new_exits:
                if new_exit.jumpkind == "Ijk_Call":
                    has_call_exit = True

            all_symbolic = True
            for new_exit in new_exits:
                if new_exit.jumpkind == "Ijk_Ret":
                    all_symbolic = False
                    break
                if not new_exit.state.se.symbolic(new_exit.target):
                    all_symbolic = False
                    break
            '''
            if all_symbolic:
                # We want to try executing this function in symbolic mode to
                # get more exits
                l.debug("Trying to symbolically solve IRSB at 0x%08x " + \
                        "in function 0x%08x", \
                        exit_addr, current_function_addr)
                if current_function_addr == exit_addr:
                    new_exits = self._symbolic_reconnoiter(current_function_addr, \
                                                       exit_addr)
                else:
                    new_exits = self._symbolic_reconnoiter(parent_addr, \
                                                       exit_addr)
                # Replace the states with concrete-mode states!
                for ex in new_exits:
                    ex.state.options = initial_options
                l.debug("Got %d exits from symbolic solving.", len(new_exits))
            '''
            for new_exit in new_exits:
                if not has_call_exit and \
                        new_exit.jumpkind == "Ijk_Ret":
                    continue
                try:
                    # Try to concretize the target. If we can't, just move on
                    # to the next target
                    target_addr = new_exit.concretize()
                except simuvex.SimValueError:
                    continue

                # Log it before we cut the tracing :)
                if new_exit.jumpkind == "Ijk_Call":
                    if current_function_addr != -1:
                        self._call_map.add_edge(current_function_addr, target_addr)
                    else:
                        self._call_map.add_node(target_addr)
                elif new_exit.jumpkind == "Ijk_Boring" or \
                        new_exit.jumpkind == "Ijk_Ret":
                    if current_function_addr != -1:
                        function_exits[current_function_addr].add(target_addr)

                # If we have traced it before, don't trace it anymore
                if target_addr in traced_address:
                    continue
                # If we have traced it in current loop, don't tract it either
                if target_addr in tmp_exit_set:
                    continue

                tmp_exit_set.add(target_addr)

                if new_exit.jumpkind == "Ijk_Call":
                    # This is a call. Let's record it
                    new_state = new_exit.state.copy()
                    # Unconstrain those parameters
                    # TODO: Support other archs as well
                    if 12 + 16 in new_state.registers.mem:
                        del new_state.registers.mem[12 + 16]
                    if 16 + 16 in new_state.registers.mem:
                        del new_state.registers.mem[16 + 16]
                    if 20 + 16 in new_state.registers.mem:
                        del new_state.registers.mem[20 + 16]
					# 0x8000000: call 0x8000045
                    remaining_exits.add((target_addr, target_addr, exit_addr, new_state))
                    l.debug("Function calls: %d", len(self._call_map.nodes()))
                elif new_exit.jumpkind == "Ijk_Boring" or \
                        new_exit.jumpkind == "Ijk_Ret":
                    new_state = new_exit.state.copy()
                    l.debug("New exit with jumpkind %s", new_exit.jumpkind)
					# FIXME: should not use current_function_addr if jumpkind is "Ijk_Ret"
                    remaining_exits.add((current_function_addr, target_addr, \
                                         exit_addr, new_state))
                elif new_exit.jumpkind == "Ijk_NoDecode":
                    # That's something VEX cannot decode!
                    # We assume we ran into a deadend
                    pass
                elif new_exit.jumpkind.startswith("Ijk_Sig"):
                    # Should not go into that exit
                    pass
                elif new_exit.jumpkind == "Ijk_TInval":
                    # ppc32: isync
					# FIXME: It is the same as Ijk_Boring! Process it later
                    pass
                elif new_exit.jumpkind == 'Ijk_Sys_syscall':
                    # Let's not jump into syscalls
                    pass
                elif new_exit.jumpkind == 'Ijk_InvalICache':
                    pass
                else:
                    raise Exception("NotImplemented")

        # Post-processing: Map those calls that are not made by call/blr
        # instructions to their targets in our map
        for src, s in function_exits.items():
            if src in self._call_map:
                for target in s:
                    if target in self._call_map:
                        self._call_map.add_edge(src, target)

        nodes = sorted(self._call_map.nodes())
        for i in range(len(nodes) - 1):
            if nodes[i] >= nodes[i + 1] - 4:
                for dst in self._call_map.successors(nodes[i + 1]):
                    self._call_map.add_edge(nodes[i], dst)
                for src in self._call_map.predecessors(nodes[i + 1]):
                    self._call_map.add_edge(src, nodes[i])
                self._call_map.remove_node(nodes[i + 1])

        #import pickle
        #pickle.dump(self._read_addr_to_run, open("read_addr_map", "wb"))
        #pickle.dump(self._write_addr_to_run, open("write_addr_map", "wb"))
        #pickle.dump(self._call_map, open("call_map", "wb"))
        #pickle.dump(function_exits, open("function_exits", "wb"))
        l.debug("Construction finished.")

    def _dbg_output(self):
        ret = ""
        ret += "Functions:\n"
        function_list = list(self._functions)
        # Sort it
        function_list = sorted(function_list)
        for f in function_list:
            ret += "0x%08x" % f

        return ret
