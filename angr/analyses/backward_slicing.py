from collections import defaultdict
from itertools import ifilter
import logging

import networkx

import simuvex

from ..annocfg import AnnotatedCFG
from ..analysis import Analysis
from ..errors import AngrBackwardSlicingError

l = logging.getLogger(name="angr.analyses.backward_slicing")

class WorkList(object):
    def __init__(self):
        self._worklist = set()

    def add(self, taint_source):
        # Scan the current list for existing TaintSource object of the same run. If
        # there exists any, combine them.
        existing_items = filter(lambda r : r.run == taint_source.run, self._worklist)
        if len(existing_items) == 0:
            self._worklist.add(taint_source)
        elif len(existing_items) == 1:
            old_ts = existing_items[0]
            self._worklist.remove(old_ts)
            taint_source.data_taints |= old_ts.data_taints
            taint_source.reg_taints |= old_ts.reg_taints
            taint_source.tmp_taints |= old_ts.tmp_taints
            # Write our combined taint source to the worklist
            self._worklist.add(taint_source)
        else:
            raise Exception("Something is wrong!")

    def pop(self):
        if len(self._worklist) > 0:
            return self._worklist.pop()
        return None

    def size(self):
        return len(self._worklist)

    def items(self):
        for ts in self._worklist:
            yield ts

class TaintSource(object):
    # taints: a set of all tainted stuff after this basic block
    def __init__(self, run, stmt_id, data_taints, reg_taints, tmp_taints, kids=None, parent=None):
        kids = [ ] if kids is None else kids

        self.run = run
        self.stmt_id = stmt_id
        self.data_taints = data_taints
        self.reg_taints = reg_taints
        self.tmp_taints = tmp_taints
        self.kids = kids
        self.parent = parent

    def equalsTo(self, obj):
        return (self.irsb == obj.irsb) and (self.stmt_id == obj.stmt_id) and (self.taints == obj.taints)

class BackwardSlicing(Analysis):

    def __init__(self, cfg, cdg, ddg, irsb, stmt_id, control_flow_slice=False):
        self._project = self._p
        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._target_irsb = irsb
        self._target_stmt_idx = stmt_id

        self.runs_in_slice = None
        self.run_statements = None

        self.construct(irsb, stmt_id, control_flow_slice=control_flow_slice)

    def annotated_cfg(self, start_point=None):
        '''
        Returns an AnnotatedCFG based on this SliceInfo.
        '''

        target_irsb_addr = self._target_irsb.addr
        target_stmt = self._target_stmt_idx
        start_point = start_point if start_point is not None else self._p.entry

        l.debug("Initializing AnnoCFG...")
        target_irsb = self._cfg.get_any_irsb(target_irsb_addr)
        anno_cfg = AnnotatedCFG(self._project, self._cfg, target_irsb_addr)
        if target_stmt is not -1:
            anno_cfg.set_last_stmt(target_irsb, target_stmt)

        start_point_addr = 0
        successors = [self._cfg.get_any_irsb(start_point)]
        processed_successors = set()
        while len(successors) > 0:
            run = successors.pop()
            if self.run_statements[run] is True:
                anno_cfg.add_simrun_to_whitelist(run)
            else:
                anno_cfg.add_statements_to_whitelist(run, self.run_statements[run])
            if isinstance(run, simuvex.SimIRSB):
                start_point_addr = run.addr
            elif isinstance(run, simuvex.SimProcedure):
                if start_point_addr == 0:
                    start_point_addr = run.addr
            processed_successors.add(run)
            new_successors = self.runs_in_slice.successors(run)
            for s in new_successors:
                anno_cfg.add_exit_to_whitelist(run, s)
                if s not in processed_successors:
                    successors.append(s)

            # TODO: expose here, maybe?
            #anno_cfg.set_path_merge_points(self._path_merge_points)

        return anno_cfg

    # With a given parameter, we try to generate a dependency graph of
    # it.
    def construct(self, irsb, stmt_id, control_flow_slice=False):
        if control_flow_slice:
            self._construct_control_flow_slice(irsb, stmt_id)
        else:
            self._construct(irsb, stmt_id)

    def _construct_control_flow_slice(self, irsb, stmt_id):
        '''
        Build a slice of the program without considering the effect of data dependencies.
        This ia an incorrect hack, but it should work fine with small programs.
        :param irsb: The target IRSB. You probably wanna get it from the CFG somehow. It
                    must exist in the CFG.
        :param stmt_id: Inex of the target statement. -1 refers to the last statement
        :return: None
        '''
        if self._cfg is None:
            l.error('Please build CFG first.')

        cfg = self._cfg.graph
        if irsb not in cfg:
            l.error('SimRun instance %s is not in the CFG.', irsb)

        reversed_cfg = networkx.DiGraph()
        # Reverse the graph
        for s, d in cfg.edges():
            reversed_cfg.add_edge(d, s)

        # Traverse forward in the reversed graph
        stack = [ ]
        stack.append(irsb)

        self.runs_in_slice = networkx.DiGraph()

        self.run_statements = { }
        while stack:
            # Pop one out
            block = stack.pop()
            if block not in self.run_statements:
                self.run_statements[block] = True
                # Get all successors of that block
                successors = reversed_cfg.successors(block)
                for succ in successors:
                    stack.append(succ)
                    self.runs_in_slice.add_edge(succ, block)

    def _construct(self, irsb, stmt_id):
        #graph = networkx.DiGraph()

        # Backward-trace from the specified statement
        # Worklist algorithm:
        # A tuple (irsb, stmt_id, taints) is put in the worklist. If
        # it is changed, we'll redo the analysis of that IRSB

        if irsb not in self._cfg.graph:
            raise AngrBackwardSlicingError('Target IRSB %s is not in the CFG.', irsb)

        if stmt_id != -1:
            path = self._project.path_generator.blank_path(state=irsb.initial_state)
            s = path.state
            actions = filter(lambda r: r.type == 'reg' and r.action == 'write' and r.stmt_idx == stmt_id,
                          s.log.actions)
            if len(actions) != 1:
                raise Exception("Invalid references. len(actions) == %d." % len(actions))
            data_reg_deps = set(actions[0].data.reg_deps)
            data_tmp_deps = set(actions[0].data.tmp_deps)
        else:
            data_reg_deps = set()
            data_tmp_deps = set()
        # TODO: Make it more elegant
        data_deps = set()
        # TODO: What's the data dependency here?

        start = TaintSource(irsb, stmt_id, data_deps, data_reg_deps, data_tmp_deps, kids=[ ])

        worklist = WorkList()
        worklist.add(start)
        processed_ts = set()
        run2TaintSource = defaultdict(list)
        self.runs_in_slice = networkx.DiGraph()
        # We are using a list here, and later on we reconstruct lists and write it to
        # self.run_statements
        run_statements = defaultdict(set)
        while worklist.size() > 0:
            ts = worklist.pop()
            # if len(ts.kids) > 0:
            #     if ts.run.addr == 0xff84cba0:
            #         import ipdb
            #         ipdb.set_trace()
            #     for kid in ts.kids:
            #         self.runs_in_slice.add_edge(ts.run, kid)
            tmp_worklist = WorkList()
            run2TaintSource[ts.run].append(ts)
            data_taint_set = ts.data_taints.copy()
            reg_taint_set = ts.reg_taints.copy()
            tmp_taint_set = ts.tmp_taints.copy()
            l.debug("<[%d]%s", len(tmp_taint_set), tmp_taint_set)
            l.debug("<[%d]%s", len(reg_taint_set), reg_taint_set)
            l.debug("<[%d]%s", len(data_taint_set), data_taint_set)

            #arch_name = ts.run.initial_state.arch.name
            if isinstance(ts.run, simuvex.SimIRSB):
                irsb = ts.run
                state = irsb.successors[0]

                print "====> Pick a new run at 0x%08x" % ts.run.addr
                # irsb.irsb.pp()
                reg_taint_set.add(self._project.arch.ip_offset)
                # Traverse the the current irsb, and taint everything related

                # Taint the default exit first
                for a in irsb.next_expr.actions:
                    if a.type == "tmp" and a.action == "read":
                        tmp_taint_set.add(a.tmp)
                # We also taint the stack pointer, so we could keep the stack balanced
                reg_taint_set.add(self._project.arch.sp_offset)

                # FIXME
                # Ugly fix for debugging the dell firmware stuff
                # if irsb.addr in [0x40906cd0, 0x40906e0c, 0x40906e14] or \
                #         irsb.addr in [0x40906d48, 0x40906c88, 0x40906d28] or \
                #         irsb.addr in [0x409067b0, 0x409067c0, 0x409067e8]:
                #     run_statements[irsb] |= set(range(0, 150))

                stmt_start_id = ts.stmt_id
                if stmt_start_id == -1:
                    actions = reversed(list(state.log.actions))
                else:
                    actions = reversed([a for a in  state.log.actions if a.stmt_idx <= stmt_start_id])

                for a in actions:
                    stmt_id = a.stmt_idx
                    if a.type == "reg" and a.action == "write":
                        if a.offset in reg_taint_set:
                            run_statements[irsb].add(stmt_id)
                            if a.offset != self._project.arch.ip_offset:
                                # Remove this taint
                                reg_taint_set.remove(a.offset)
                            # Taint all its dependencies
                            for reg_dep in a.data.reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in a.data.tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    elif a.type == "tmp" and a.action == "write":
                        if a.tmp in tmp_taint_set:
                            run_statements[irsb].add(stmt_id)
                            # Remove this taint
                            tmp_taint_set.remove(a.tmp)
                            # Taint all its dependencies
                            for reg_dep in a.data.reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in a.data.tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    #elif type(a) == SimRegRead:
                        # l.debug("Ignoring SimRegRead")
                    #    pass
                    #elif type(a) == SimTmpRead:
                        # l.debug("Ignoring SimTmpRead")
                    #    pass
                    #elif type(a) == SimMemRef:
                        # l.debug("Ignoring SimMemRef")
                    #    pass
                    elif a.type == "mem" and a.action == "read":
                        if irsb.addr in self._ddg._graph and stmt_id in self._ddg._graph[irsb.addr]:
                            dependency_set = self._ddg._graph[irsb.addr][stmt_id]
                            for dependent_run_addr, dependent_stmt_id in dependency_set:
                                dependent_run = self._cfg.get_any_irsb(dependent_run_addr)
                                if isinstance(dependent_run, simuvex.SimIRSB):
                                    # It's incorrect to do this:
                                    # 'run_statements[dependent_run].add(dependent_stmt_id)'
                                    # We should add a dependency to that SimRun object, and reanalyze
                                    # it by putting it to our worklist once more

                                    # Check if we need to reanalyze that block
                                    new_data_taint_set = set()
                                    new_data_taint_set.add(dependent_stmt_id)
                                    dependent_runs = self._cfg.get_all_irsbs(dependent_run_addr)
                                    for d_run in dependent_runs:
                                        new_ts = TaintSource(d_run, -1,
                                            new_data_taint_set, set(), set())
                                        tmp_worklist.add(new_ts)
                                        l.debug("%s added to temp worklist.", d_run)
                                else:
                                    # A SimProcedure instance
                                    new_data_taint_set = { -1 }
                                    dependent_runs = self._cfg.get_all_irsbs(dependent_run_addr)
                                    for d_run in dependent_runs:
                                        new_ts = TaintSource(d_run, -1, new_data_taint_set,
                                                        set(), set())
                                        tmp_worklist.add(new_ts)
                                    l.debug("%s added to temp worklist.", dependent_run)
                    elif a.type == "mem" and a.action == "write":
                        if stmt_id in data_taint_set:
                            data_taint_set.remove(stmt_id)
                            run_statements[irsb].add(stmt_id)
                            for d in a.data.reg_deps:
                                reg_taint_set.add(d)
                            for d in a.addr.reg_deps:
                                reg_taint_set.add(d)
                            for d in a.data.tmp_deps:
                                tmp_taint_set.add(d)
                            for d in a.addr.tmp_deps:
                                tmp_taint_set.add(d)
                            # TODO: How do we handle other data dependencies here? Or if there is any?
                    else:
                        pass
            elif isinstance(ts.run, simuvex.SimProcedure):
                sim_proc = ts.run
                state = sim_proc.successors[0]
                actions = reversed(list(state.log.actions))
                for a in actions:
                    if a.type == "reg" and a.action == "write":
                        if a.offset in reg_taint_set:
                            if a.offset != self._project.arch.ip_offset:
                                # Remove this taint
                                reg_taint_set.remove(a.offset)
                            # Taint all its dependencies
                            for reg_dep in a.data.reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in a.data.tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    elif a.type == "tmp" and a.action == "write":
                        if a.tmp in tmp_taint_set:
                            # Remove this taint
                            tmp_taint_set.remove(a.tmp)
                            # Taint all its dependencies
                            for reg_dep in a.data.reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in a.data.tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    elif a.type == "reg" and a.action == "read":
                        # Adding new ref!
                        reg_taint_set.add(a.offset)
                    elif a.type == "mem" and a.action == "read":
                        if sim_proc.addr in self._ddg._graph:
                            dependency_set = self._ddg._graph[sim_proc.addr][-1]
                            for dependent_run_addr, dependent_stmt_id in dependency_set:
                                data_set = set()
                                data_set.add(dependent_stmt_id)
                                dependent_runs = self._cfg.get_all_irsbs(dependent_run_addr)
                                for d_run in dependent_runs:
                                    new_ts = TaintSource(d_run, -1, data_set, set(), set())
                                    tmp_worklist.add(new_ts)
                                    l.debug("%s added to temp worklist.", d_run)
                    elif a.type == "mem" and a.action == "write":
                        if -1 in data_taint_set:
                            for d in a.data.reg_deps:
                                reg_taint_set.add(d)
                            for d in a.addr.reg_deps:
                                reg_taint_set.add(d)
                            for d in a.data.tmp_deps:
                                tmp_taint_set.add(d)
                            for d in a.addr.tmp_deps:
                                tmp_taint_set.add(d)
                            # TODO: How do we handle other data dependencies here? Or if there is any?
                    else:
                        pass
                    # Loop ends

                if -1 in data_taint_set:
                    data_taint_set.remove(-1)
            else:
                raise Exception("Unsupported SimRun type %s" % type(ts.run))

            l.debug(">[%d]%s", len(tmp_taint_set), tmp_taint_set)
            l.debug(">[%d]%s", len(reg_taint_set), reg_taint_set)
            l.debug(">[%d]%s", len(data_taint_set), data_taint_set)
            l.debug("Worklist size: %d", worklist.size())
            # symbolic_data_taint_set = set()
            # for d in data_taint_set:
            #     if d.is_symbolic():
            #         symbolic_data_taint_set.add(d)

            # We create the TaintSource object using the old taints from ts, not the new ones
            # (tmp_taint_set, reg_taint_set, and data_taint_set). Then TS object is put into
            # processed_ts.
            processed_ts.add(TaintSource(ts.run, -1, ts.data_taints, ts.reg_taints, ts.tmp_taints, kids=ts.kids))
            # Get its predecessors from our CFG
            # if ts.run.addr == 0xff84cc50:
            #     import ipdb
            #     ipdb.set_trace()
            if len(data_taint_set) > 0 or len(reg_taint_set) > 0:
                predecessors = self._cfg.get_predecessors(ts.run)
                for p in predecessors:
                    new_reg_taint_set = reg_taint_set.copy()
                    new_data_taint_set = data_taint_set.copy()
                    new_tmp_taint_set = tmp_taint_set.copy()
                    kids_set = set()

                    if isinstance(p, simuvex.SimIRSB):
                        # If it's not a boring exit from its predecessor, we shall
                        # search for the last branching, and taint the temp variable
                        # there.
                        flat_successors = p.flat_successors
                        # Remove the simulated return exit
                        # YAN: commented this out because the pseudo-rets no longer show as reachable, and flat_exits takes reachable by default
                        #if len(flat_exits) > 0 and \
                        #       flat_exits[0].jumpkind == "Ijk_Call":
                        #   assert flat_exits[-1].jumpkind == "Ijk_Ret"
                        #   del flat_exits[-1]
                        if len(flat_successors) > 1:
                            successors = [suc for suc in flat_successors if
                                    not suc.se.symbolic(suc.ip) and
                                    suc.se.exactly_int(suc.ip, default=None) == ts.run.addr]
                            if len(successors) == 0 or not self._p.sim_run(successors[0]).default_exit:
                                # It might be 0 sometimes...
                                # Search for the last branching exit, just like
                                #     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
                                # , and then taint the temp variable inside if predicate
                                cmp_stmt_id, cmp_tmp_id = self._search_for_last_branching_statement(p.statements)
                                if cmp_stmt_id is not None:
                                    new_tmp_taint_set.add(cmp_tmp_id)
                                    run_statements[p].add(cmp_stmt_id)

                    l.debug("%s Got new predecessor %s", ts.run, p)
                    new_ts = TaintSource(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set, kids=list(kids_set), parent=ts.run)
                    tmp_worklist.add(new_ts)
                    # Add it to our map
                    self.runs_in_slice.add_edge(p, ts.run)

            # Let's also search for predecessors on control dependency graph
            cdg_predecessors = self._cdg.get_predecessors(ts.run)
            for p in cdg_predecessors:
                new_reg_taint_set = reg_taint_set.copy()
                new_data_taint_set = data_taint_set.copy()
                new_tmp_taint_set = set()
                kids_set = set()
                if isinstance(p, simuvex.SimIRSB):
                    # Search for the last branching exit, just like
                    #     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
                    # , and then taint the temp variable inside if predicate
                    cmp_stmt_id, cmp_tmp_id = self._search_for_last_branching_statement(p.statements)
                    if cmp_stmt_id is not None:
                        new_tmp_taint_set.add(cmp_tmp_id)
                        run_statements[p].add(cmp_stmt_id)

                l.debug("%s Got new control-dependency predecessor %s", ts.run, p)
                new_ts = TaintSource(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set, kids=list(kids_set))
                tmp_worklist.add(new_ts)
                # Add it to our map
                self.runs_in_slice.add_edge(p, ts.run)

            # Merge temp worklist with the real worklist
            for taint_source in tmp_worklist.items():
                # Merge it with existing items in processed_ts
                existing_tses = filter(lambda r : r.run == taint_source.run, processed_ts) #pylint:disable=W0640
                if len(existing_tses) > 0:
                    existing_ts = existing_tses[0]
                    if existing_ts.reg_taints >= taint_source.reg_taints and \
                            existing_ts.data_taints >= taint_source.data_taints and \
                            existing_ts.tmp_taints >= taint_source.tmp_taints:
                        l.debug("Ignore predecessor %s", taint_source.run)
                        continue
                    else:
                        # Remove the existing one
                        processed_ts.remove(existing_ts)
                        # Merge the old taint sets into new taint sets
                        taint_source.reg_taints |= existing_ts.reg_taints
                        taint_source.data_taints |= existing_ts.data_taints
                        taint_source.tmp_taints |= existing_ts.tmp_taints

                l.debug("%s added to real worklist.", taint_source.run)
                # Add it into the real worklist
                worklist.add(taint_source)

            # raw_input("Press any key to continue...")

        # Reconstruct the run_statements
        self.run_statements = defaultdict(list)
        for run, s in run_statements.items():
            self.run_statements[run] = list(s)

    def _search_for_last_branching_statement(self, statements): #pylint:disable=R0201
        '''
        Search for the last branching exit, just like
        #   if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
        and then taint the temp variable inside if predicate
        '''
        cmp_stmt_id = None
        cmp_tmp_id = None
        statement_ids = range(len(statements))
        for stmt_id in reversed(statement_ids):
            refs = statements[stmt_id].refs
            # Ugly implementation here
            has_code_ref = False
            for r in refs:
                if isinstance(r, SimCodeRef):
                    has_code_ref = True
                    break
            if has_code_ref:
                tmp_ref = next(ifilter(lambda r: isinstance(r, SimTmpRead), refs), None)
                if tmp_ref is not None:
                    cmp_tmp_id = tmp_ref.tmp
                    cmp_stmt_id = stmt_id
                    break
                else:
                    raise Exception("Please report to Fish")
        return cmp_stmt_id, cmp_tmp_id
