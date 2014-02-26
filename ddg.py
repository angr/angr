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
        worklist = set()
        # Added the first container into the worklist
        initial_container = AddrToRefContainer(self._cfg.get_irsb((None, None, self._entry_point)), defaultdict(set))
        worklist.add(initial_container)
        analyzed_runs = set()
        analyzed_containers = {}
        while len(worklist) > 0:
            container = worklist.pop()
            run = container.run
            # If we updated our addr_to_ref map, we should set redo_flag to
            # True, then all of its successors will be reanalyzed
            redo_flag = container.reanalyze_successors
            if isinstance(run, SimIRSB):
                irsb = run
                l.debug("Running %s", irsb)
                # Simulate the execution of this irsb.
                # For MemWriteRef, fill the addr_to_ref dict with every single concretizable
                # memory address, and ignore those symbolic ones
                # For MemReadRef, get its related MemoryWriteRef from our dict
                # TODO: Is it possible to trace memory operations even if the memory is not
                # concretizable itself?
                statements = irsb.statements
                for i in range(len(statements)):
                    stmt = statements[i]
                    refs = stmt.refs
                    if len(refs) > 0:
                        real_ref = refs[len(refs) - 1]
                        if type(real_ref) == SimMemWrite:
                            addr = real_ref.addr
                            if not addr.is_symbolic():
                                concrete_addr = addr.any()
                                tpl = (irsb.addr, i)
                                if tpl not in container.addr_to_ref[concrete_addr]:
                                    container.addr_to_ref[concrete_addr].add(tpl)
                                    redo_flag = True
                            else:
                                self._symbolic_mem_ops.add((irsb, real_ref))
                    for ref in refs:
                        if type(ref) == SimMemRead:
                            addr = ref.addr
                            if not addr.is_symbolic():
                                concrete_addr = addr.any()
                                if concrete_addr in container.addr_to_ref:
                                    self._ddg[irsb.addr][i] |= (container.addr_to_ref[concrete_addr])
                            else:
                                self._symbolic_mem_ops.add((irsb, ref))
            elif isinstance(run, SimProcedure):
                sim_proc = run
                l.debug("Running %s", sim_proc)
                refs = sim_proc.refs()
                for ref in refs:
                    if isinstance(ref, SimMemRead):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            concrete_addr = addr.any()
                            # print sim_proc
                            # print "0x%08x" % concrete_addr
                            if concrete_addr in container.addr_to_ref:
                                self._ddg[sim_proc.addr][-1] |= (container.addr_to_ref[concrete_addr])
                                # print "In list"
                        else:
                            self._symbolic_mem_ops.add((sim_proc, ref))
                    elif isinstance(ref, SimMemWrite):
                        addr = ref.addr
                        if not addr.is_symbolic():
                            concrete_addr = addr.any()
                            tpl = (sim_proc.addr, -1)
                            if tpl not in container.addr_to_ref[concrete_addr]:
                                container.addr_to_ref[concrete_addr].add((sim_proc.addr, -1))
                                redo_flag = True
                        else:
                            self._symbolic_mem_ops.add((sim_proc, ref))

            analyzed_runs.add(run)
            analyzed_containers[run] = container

            # Get successors of the current irsb,
            successors = self._cfg.get_successors(run)
            if redo_flag:
                for successor in successors:
                    if successor in analyzed_runs:
                        analyzed_runs.remove(successor)
            # ... and add them to our worklist with a shallow copy of the addr_to_ref dict
            for successor in successors:
                if successor not in analyzed_runs:
                    # Let's see if there is any changes in the addresses dict
                    new_addr_to_ref = container.addr_to_ref.copy()
                    new_container = None
                    if successor in analyzed_containers:
                        old_container = analyzed_containers[successor]
                        new_container = AddrToRefContainer(successor, old_container.addr_to_ref, reanalyze_successors=True)
                        if not new_container.combine(container.addr_to_ref):
                            # There isn't any new addresses
                            continue
                    if new_container is None:
                        new_container = AddrToRefContainer(successor, container.addr_to_ref.copy())
                    worklist.add(new_container)

        self._solve_symbolic_mem_operations()

class AddrToRefContainer(object):
    def __init__(self, run, addr_to_ref, reanalyze_successors=False):
        self.run = run
        self.addr_to_ref = addr_to_ref
        self.reanalyze_successors = reanalyze_successors

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
