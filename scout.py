import logging

import networkx

import simuvex
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
            print ">start = %d, end = %d, mid = %d" % (start, end, mid)
            tpl = self._list[mid]
            if addr < tpl[0]:
                end = mid
            elif addr >= tpl[1]:
                start = mid + 1
            else:
                # Overlapped :(
                start = end
                break
            print "<start = %d, end = %d, mid = %d" % (start, end, mid)
        return start

    def _merge_check(self, address, size, idx):
        # Shall we merge it?
        merged = False
        if idx > 0:
            tpl = self._list[idx - 1]
            if address == tpl[1]:
                self._list[idx - 1] = (tpl[0], address + size)
                merged = True
        if not merged:
            if idx == len(self._list):
                self._list.append((address, address + size))
            else:
                self._list.insert(idx, (address, address + size))

    def next_free_pos(self, address):
        idx = self._search(address + 1)
        if address >= self._list[idx][0] and address < self._list[idx][1]:
            # Occupied
            i = idx
            while i < len(self._list) and \
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
        if len(self._list) == 0:
            self._list.append((address, address + size))
            return
        # Find adjacent element in our list
        idx = self._search(address)
        print idx
        if idx == len(self._list):
            # We should append at the end
            self._merge_check(address, size, idx)
        else:
            tpl = self._list[idx]
            # Overlap check
            if address <= tpl[0] and address + size >= tpl[0] or \
                    address <= tpl[1] and address + size >= tpl[1]:
                new_start = min(address, tpl[0])
                new_end = max(address + size, tpl[1])
                self._list[idx] = (new_start, new_end)
            else:
                # It's not overlapped with this one
                # Shall we merge it with the previous one?
                self._merge_check(address, size, idx)

class Scout(object):
    '''
    We iteratively find functions inside the given binary, and build a graph on
    top of that to see if there is an entry or not.
    '''
    def __init__(self, project, starting_point):
        self._project = project
        self._starting_point = starting_point

        self._next_addr = starting_point
        # Starting point of functions
        self._functions = None
        # Calls between functions
        self._call_map = None
        # Create the segment list
        self._seg_list = SegmentList()

    def _get_next_addr_to_search(self):
        # TODO: Take care of those functions that are already generated
        curr_addr = self._next_addr
        # Determine the size of that IRSB
        # Note: we don't care about SimProcedure at this moment, as we want to
        # get as many functions as possible
        s_irsb = None
        instr_alignment = \
            self._project.initial_state(mode="static").arch.instruction_alignment
        while s_irsb is None:
            s_ex = simuvex.SimExit(addr=curr_addr, \
                            state=self._project.initial_state(mode="static"))
            try:
                s_irsb = self._project.sim_block(s_ex)
            except simuvex.s_irsb.SimIRSBError:
                # We cannot build functions there
                # Move on to next possible position
                s_irsb = None
                # TODO: Handle strings
                curr_addr = \
                    self._seg_list.next_free_pos(curr_addr + instr_alignment - 1)
                if curr_addr % instr_alignment > 0:
                    curr_addr = curr_addr - curr_addr % instr_alignment + \
                        instr_alignment

        block_size = s_irsb.irsb.size()
        self._next_addr = curr_addr + block_size
        l.debug("Returning new recon address: 0x%08x", curr_addr)
        return curr_addr

    def reconnoiter(self):
        '''
        The basic idea is simple: start from a specific point, try to construct
        functions as much as we can, and maintain a function distribution graph
        and a call graph simultaneously. Repeat searching until we come to the
        end that there is no now function to be found.
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
        while True:
            if len(remaining_exits) == 0:
                # Load a possible position
                remaining_exits.add((-1, self._get_next_addr_to_search()))

            current_function_addr, exit_addr = remaining_exits.pop()
            if current_function_addr != -1:
                l.debug("Tracing new exit 0x%08x in function 0x%08x", \
                        exit_addr, current_function_addr)
            else:
                l.debug("Tracing new exit 0x%08x", exit_addr)
            traced_address.add(exit_addr)
            state = self._project.initial_state(mode="static")
            # Get a basic block
            s_ex = simuvex.SimExit(addr=exit_addr, state=state)
            try:
                s_run = self._project.sim_run(s_ex)
            except simuvex.s_irsb.SimIRSBError:
                continue
            except angr.errors.AngrException:
                # "No memory at xxx"
                continue

            # Mark that part as occupied
            if isinstance(s_run, simuvex.SimIRSB):
                self._seg_list.occupy(exit_addr, s_run.irsb.size())
            new_exits = s_run.exits()
            has_call_exit = False
            for new_exit in new_exits:
                if not has_call_exit and \
                        new_exit.jumpkind == "Ijk_Ret":
                    continue
                try:
                    # Try to concretize the target. If we can't, just move on
                    # to the next target
                    target_addr = new_exit.concretize()
                except simuvex.s_value.ConcretizingException:
                    continue
                if target_addr in traced_address:
                    continue
                if new_exit.jumpkind == "Ijk_Call":
                    has_call_exit = True
                    # This is a call. Let's record it
                    remaining_exits.add((target_addr, target_addr))
                    if current_function_addr != -1:
                        self._call_map.add_edge(current_function_addr, target_addr)
                    else:
                        self._call_map.add_node(target_addr)
                elif new_exit.jumpkind == "Ijk_Boring" or \
                        new_exit.jumpkind == "Ijk_Ret":
                    remaining_exits.add((current_function_addr, target_addr))
                elif new_exit.jumpkind == "Ijk_NoDecode":
                    # That's something VEX cannot decode!
                    # We assume we ran into a deadend
                    pass
                elif new_exit.jumpkind.startswith("Ijk_Sig"):
                    # Should not go into that exit
                    pass
                else:
                    raise Exception("NotImplemented")

    def _dbg_output(self):
        ret = ""
        ret += "Functions:\n"
        function_list = list(self._functions)
        # Sort it
        function_list = sorted(function_list)
        for f in function_list:
            ret += "0x%08x" % f

        return ret
