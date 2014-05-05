from collections import defaultdict
from simuvex.s_ref import RefTypes, SimRegRead, SimRegWrite, SimTmpRead, SimTmpWrite, SimMemRead, SimMemWrite
from simuvex import SimIRSB, SimProcedure
import logging

l = logging.getLogger("angr.ddg")
l.setLevel(logging.DEBUG)

class DDG(object):
    def __init__(self, cfg, entry_point):
        self._cfg = cfg
        self._entry_point = entry_point

        self._ddg = defaultdict(lambda:defaultdict(set))
        self._symbolic_mem_ops = set()

    def debug_print(self):
        l.debug(self._ddg)

    def _trace_source(self, init_run, init_ref):
        '''
        Trace the sources (producers) of a given ref
        '''
        l.debug("Tracing source for symbolic memory dep %s of %s", init_ref, init_run)
        sources = set()
        # Memorization
        traced = {}

        init_stmt_id = init_ref.stmt_idx
        init_reg_deps = set()
        init_tmp_deps = set()
        real_ref = init_run.statements[init_stmt_id].refs[-1]
        init_reg_deps |= set(list(real_ref.data_reg_deps))
        init_tmp_deps |= set(list(real_ref.data_tmp_deps))
        if type(real_ref) == SimMemWrite:
            init_reg_deps |= set(list(real_ref.addr_reg_deps))
            init_tmp_deps |= set(list(real_ref.addr_tmp_deps))
        stack = [(init_run, init_stmt_id, init_reg_deps, init_tmp_deps)]
        while len(stack) > 0:
            run, stmt_id, reg_deps, tmp_deps = stack.pop()
            l.debug("Traversing %s", run)
            # Added to traced set
            traced[run.addr] = reg_deps
            reg_dep_to_stmt_id = {}

            if isinstance(run, SimIRSB):
                irsb = run
                if stmt_id == -1:
                    stmt_ids = range(len(irsb.statements))
                else:
                    stmt_ids = range(stmt_id + 1)
                stmt_ids.reverse()

                for stmt_id in stmt_ids:
                    stmt = irsb.statements[stmt_id]
                    if len(stmt.refs) > 0:
                        real_ref = stmt.refs[-1]
                        if type(real_ref) == SimRegWrite and real_ref.offset in reg_deps:
                            reg_dep_to_stmt_id[real_ref.offset] = stmt_id
                            reg_deps.remove(real_ref.offset)
                            reg_deps |= set(list(real_ref.data_reg_deps))
                            tmp_deps |= set(list(real_ref.data_tmp_deps))
                        elif type(real_ref) == SimTmpWrite and real_ref.tmp in tmp_deps:
                            tmp_deps.remove(real_ref.tmp)
                            reg_deps |= set(list(real_ref.data_reg_deps))
                            tmp_deps |= set(list(real_ref.data_tmp_deps))
            elif isinstance(run, SimProcedure):
                refs = run.refs()
                refs.reverse()
                for ref in refs:
                    if type(ref) == SimRegWrite and ref.offset in reg_deps:
                        reg_dep_to_stmt_id[ref.offset] = -1
                        reg_deps.remove(ref.offset)
                        reg_deps |= set(list(ref.data_reg_deps))
                        tmp_deps |= set(list(ref.data_tmp_deps))
                    elif type(ref) == SimTmpWrite and ref.tmp in tmp_deps:
                        tmp_deps.remove(ref.tmp)
                        reg_deps |= set(list(ref.data_reg_deps))
                        tmp_deps |= set(list(ref.data_tmp_deps))

            if len(reg_deps) > 0:
                predecessors = self._cfg.get_predecessors(run)
                for s in predecessors:
                    tpl = (s.addr, reg_deps)
                    if s.addr not in traced:
                        stack.append((s, -1, reg_deps.copy(), set()))
                    else:
                        old_reg_deps = traced[s.addr]
                        if not reg_deps.issubset(old_reg_deps):
                            new_reg_deps = reg_deps.copy()
                            new_reg_deps |= old_reg_deps
                            stack.append((s, -1, new_reg_deps, set()))
            for reg, stmt_id in reg_dep_to_stmt_id.items():
                sources.add((run.addr, stmt_id))
            if len(reg_deps) == 0 or len(predecessors) == 0:
                # This is the end of the u-d chain
                # FIXME: What if there is a loop, and len(successors) never == 0?
                for reg in reg_deps:
                    if reg not in reg_dep_to_stmt_id:
                        # It's never been written before
                        # We use a fake run.addr and stmt_id so that we don't lose them
                        l.debug("Register %d has never been assigned a value before.", reg)
                        sources.add((-1 * reg, -1))
                    else:
                        # sources.add((run.addr, reg_dep_to_stmt_id[reg]))
                        # They have already been added to sources
                        pass

        return sources

    def _solve_symbolic_mem_operations(self):
        '''
        We try to resolve symbolic memory operations in the following manner:
        For each memory operation, trace the pointer from its root producers.
        And then relate each memory read with all memory writes that has shared
        producers with it.
        It's imprecise and could be over-approximating, but it's better than
        losing dependencies.
        '''
        # irsb, stmt_id => list of tuples (irsb, ref)
        mem_read_producers = defaultdict(list)
        mem_write_producers = defaultdict(list)
        for irsb, ref in self._symbolic_mem_ops:
            sources = self._trace_source(irsb, ref)
            for src_irsb_addr, stmt_id in sources:
                if type(ref) == SimMemRead:
                    mem_read_producers[(src_irsb_addr, stmt_id)].append((irsb.addr, ref))
                elif type(ref) == SimMemWrite:
                    mem_write_producers[(src_irsb_addr, stmt_id)].append((irsb.addr, ref))

        for tpl, lst_writes in mem_write_producers.items():
            if tpl in mem_read_producers:
                lst_reads = mem_read_producers[tpl]
                for read_irsb, read_ref in lst_reads:
                    for write_irsb, write_ref in lst_writes:
                        self._ddg[read_irsb][read_ref.stmt_idx].add((write_irsb, write_ref.stmt_idx))

    def construct(self):
        '''
    We track the following types of memory access:
    - (Intra-functional) Stack read/write.
        Trace changes of stack pointers inside a function, and the dereferences
        of stack pointers.
    - (Inter-functional) Stack read/write.
        TODO
    - (Global) Static memory positions.
        Keep a map of all accessible memory positions to their source statements
        per function. After that, we traverse the CFG and link each pair of
        reads/writes together in the order of control-flow.
    - (Intra-functional) Indirect memory access
        TODO

    In this way it's an O(N) algorithm, where N is the number of all functions
    (with context sensitivity). The old worklist algorithm is exponential in the
    worst case.
        '''
        # Stack access
        # Unfortunately, we have no idea where a function is, and it's better
        # not to rely on function identification methods. So we just traverse
        # the CFG once, and maintain a map of scanned IRSBs so that we scan
        # each IRSB only once.
        scanned_runs = set()
        initial_irsb = self._cfg.get_irsb((None, None, self._entry_point))
        # We maintain a calling stack so that we can limit all analysis within
        # the range of a single function.
        # Without function analysis, our approach is quite simple: If there is
        # an SimExit whose jumpkind is 'Ijk_Call', then we create a new frame
        # in calling stack. A frame is popped out if there exists an SimExit
        # that has 'Ijk_Ret' as its jumpkind.
        initial_wrapper = RunWrapper(initial_irsb)
        # All pending SimRuns
        run_stack = [initial_wrapper]
        while len(run_stack) > 0:
            run_wrapper = run_stack.pop()

            # Get the current calling stack
            current_stack = run_wrapper.call_stack

            run = run_wrapper.run
            if run in scanned_runs:
                continue
            scanned_runs.add(run)
            l.debug("Scanning %s", run)

            # Expand the current SimRun
            successors = self._cfg.get_successors(run)
            # TODO: It is buggy here. We are losing correlation between run.exits
            # and each successor in the CFG!
            for successor in successors:
                if successor in scanned_runs:
                    continue

                new_stack = current_stack[::] # Make a copy
                if run.exits()[0].jumpkind == "Ijk_Call":
                    # Create a new function frame
                    new_stack.append(run_wrapper)
                elif run.exits()[0].jumpkind == "Ijk_Ret":
                    if len(new_stack) > 0:
                        # Pop out the latest function frame
                        new_stack.pop()
                    else:
                        # We are returning from somewhere, but the stack is
                        # already empty.
                        # Something must have went wrong.
                        l.warning("Stack is already empty before popping things out")
                else:
                    # Do nothing :)
                    pass
                wrapper = RunWrapper(successor, \
                        addr_to_ref=run_wrapper.addr_to_ref, \
                        call_stack=new_stack)
                run_stack.append(wrapper)

            if isinstance(run, SimIRSB):
                irsb = run

                # Simulate the execution of this IRSB.
                # For MemWriteRef, fill the addr_to_ref dict with every single
                # concretizable memory address, and just ignore symbolic ones
                # for now.
                # For MemReadRef, we get its related MemWriteRef from our dict
                stmts = irsb.statements
                for i in range(len(stmts)):
                    stmt = stmts[i]
                    refs = stmt.refs
                    if len(refs) == 0:
                        continue
                    # Obtain the real Ref of current statement
                    real_ref = refs[-1]
                    if type(real_ref) == SimMemWrite:
                        addr = real_ref.addr
                        if not addr.is_symbolic():
                            # It's not symbolic. Try to concretize it.
                            concrete_addr = addr.any()
                            # Create the tuple of (simrun_addr, stmt_id)
                            tpl = (irsb.addr, i)
                            run_wrapper.addr_to_ref[concrete_addr] = tpl
                            l.debug("Memory write to addr 0x%x, stmt id = %d", concrete_addr, i)
                        else:
                            # Add it to our symbolic memory operation list. We
                            # will process them later.
                            self._symbolic_mem_ops.add((irsb, real_ref))
                    for ref in refs:
                        if type(ref) == SimMemRead:
                            addr = ref.addr
                            if not addr.is_symbolic():
                                # Not symbolic. Try to concretize it.
                                concrete_addr = addr.any()
                                # Check if this address has been written before.
                                # Note: we should check every single call frame,
                                # from the latest to earliest, until we come
                                # across that address.
                                reversed_range = range(len(current_stack))
                                reversed_range.reverse()
                                for j in reversed_range:
                                    con_ = current_stack[j]
                                    if concrete_addr in con_.addr_to_ref:
                                        # Luckily we found it!
                                        # Record it in our internal dict
                                        self._ddg[irsb.addr][i].add(
                                            con_.addr_to_ref[concrete_addr])
                                        break
                                # TODO: What if we have never seen this address
                                # before? It might be an address whose value is
                                # initialized somewhere else, or an address that
                                # contains initialized value.
                            else:
                                self._symbolic_mem_ops.add((irsb, ref))
            else:
                # SimProcedure
                sim_proc = run
                l.debug("Scanning %s", sim_proc)

                refs = sim_proc.refs()
                for ref in refs:
                    if isinstance(ref, SimMemWrite):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            # Record it
                            # Not symbolic. Try to concretize it.
                            concrete_addr = addr.any()
                            # Create the tuple of (simrun_addr, stmt_id)
                            tpl = (sim_proc.addr, i)
                            run_wrapper.addr_to_ref[concrete_addr] = tpl
                        else:
                            self._symbolic_mem_ops.add((sim_proc, ref))
                    elif isinstance(ref, SimMemRead):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            # Not symbolic. Try to concretize it.
                            concrete_addr = addr.any()
                            reversed_range = range(len(current_stack))
                            reversed_range.reverse()
                            for j in reversed_range:
                                con_ = current_stack[j]
                                if concrete_addr in con_.addr_to_ref:
                                    # Luckily we found it!
                                    # Record it in our internal dict
                                    self._ddg[sim_proc.addr][-1].add(
                                        con_.addr_to_ref[concrete_addr])
                                    break
                            # TODO: what if we didn't see that address before?
                        else:
                            self._symbolic_mem_ops.add((sim_proc, ref))

        self._solve_symbolic_mem_operations()

class RunWrapper(object):
    '''
We keep an RunWrapper object for each function (with context sensitivity, it's
an AddrToRefContainer object for each [function, context] pair). It contains a
list of all runs inside this function, a dict addr_to_ref storing all
references between addresses and a [simrun_addr, stmt_id] pair, and a calling
stack.
    '''
# TODO: We might want to change the calling stack into a branching list with
# CoW supported.
    def __init__(self, run, addr_to_ref=None, call_stack=None, reanalyze_successors=False):
        self.run = run
        if addr_to_ref is None:
            self.addr_to_ref = {}
        else:
            self.addr_to_ref = addr_to_ref

        if call_stack is None:
            self.call_stack = []
        else:
            # We DO NOT make a copy of the provided stack object
            self.call_stack = call_stack

        self.reanalyze_successors = reanalyze_successors
'''
    def combine(self, new_addr_to_ref):
        altered = False
        for k, v in new_addr_to_ref.items():
            if k not in self.addr_to_ref:
                self.addr_to_ref[k] = v.copy()
                altered = True
            else:
                if not v.issubset(self.addr_to_ref[k]):
                    altered = True
                    self.addr_to_ref[k] |= v
        return altered
'''
