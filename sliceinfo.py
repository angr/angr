from collections import defaultdict
import networkx
from simuvex.s_ref import RefTypes, SimRegWrite, SimRegRead, SimTmpWrite, SimTmpRead, SimMemRef, SimMemRead, SimMemWrite, SimCodeRef
from simuvex import SimIRSB, SimProcedure
import simuvex
import logging

l = logging.getLogger(name="angr.sliceinfo")

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

class SliceInfo(object):
    def __init__(self, binary, project, cfg, cdg, ddg):
        self._binary = binary
        self._project = project
        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self.runs_in_slice = None
        self.run_statements = None

    # With a given parameter, we try to generate a dependency graph of
    # it.
    def construct(self, irsb, stmt_id):
        l.debug("construct sliceinfo from entrypoint 0x%08x" % (self._binary.entry()))
        graph = networkx.DiGraph()

        # Backward-trace from the specified statement
        # Worklist algorithm:
        # A tuple (irsb, stmt_id, taints) is put in the worklist. If
        # it is changed, we'll redo the analysis of that IRSB

        refs = filter(lambda r: r.stmt_idx == stmt_id, irsb.refs()[SimRegWrite])
        if len(refs) != 1:
            raise Exception("Invalid references. len(refs) == %d." % len(refs))
        # TODO: Make it more elegant
        data_dep_set = set()
        # TODO: What's the data dependency here?
        start = TaintSource(irsb, stmt_id, data_dep_set, set(refs[0].data_reg_deps), set(refs[0].data_tmp_deps), kids=[])
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

            arch_name = ts.run.initial_state.arch.name
            if type(ts.run) == SimIRSB:
                irsb = ts.run
                print "====> Pick a new run at 0x%08x" % ts.run.addr
                # irsb.irsb.pp()
                reg_taint_set.add(simuvex.Architectures[arch_name].ip_offset)
                # Traverse the the current irsb, and taint everything related
                stmt_start_id = ts.stmt_id
                if stmt_start_id == -1:
                    stmt_start_id = len(irsb.statements) - 1
                statement_ids = range(stmt_start_id + 1)
                statement_ids.reverse()
                # Taint the default exit first
                for ref in irsb.next_expr.refs:
                    if type(ref) == SimTmpRead:
                        tmp_taint_set.add(ref.tmp)
                # We also taint the stack pointer, so we could keep the stack balanced
                reg_taint_set.add(simuvex.Architectures[arch_name].sp_offset)
                for stmt_id in statement_ids:
                    # l.debug(reg_taint_set)
                    refs = irsb.statements[stmt_id].refs
                    # l.debug(str(stmt_id) + " : %s" % refs)
                    # irsb.statements[stmt_id].stmt.pp()
                    for ref in refs:
                        if type(ref) == SimRegWrite:
                            if ref.offset in reg_taint_set:
                                run_statements[irsb].add(stmt_id)
                                if ref.offset != simuvex.Architectures[arch_name].ip_offset:
                                    # Remove this taint
                                    reg_taint_set.remove(ref.offset)
                                # Taint all its dependencies
                                for reg_dep in ref.data_reg_deps:
                                    reg_taint_set.add(reg_dep)
                                for tmp_dep in ref.data_tmp_deps:
                                    tmp_taint_set.add(tmp_dep)
                        elif type(ref) == SimTmpWrite:
                            if ref.tmp in tmp_taint_set:
                                run_statements[irsb].add(stmt_id)
                                # Remove this taint
                                tmp_taint_set.remove(ref.tmp)
                                # Taint all its dependencies
                                for reg_dep in ref.data_reg_deps:
                                    reg_taint_set.add(reg_dep)
                                for tmp_dep in ref.data_tmp_deps:
                                    tmp_taint_set.add(tmp_dep)
                        elif type(ref) == SimRegRead:
                            # l.debug("Ignoring SimRegRead")
                            pass
                        elif type(ref) == SimTmpRead:
                            # l.debug("Ignoring SimTmpRead")
                            pass
                        elif type(ref) == SimMemRef:
                            # l.debug("Ignoring SimMemRef")
                            pass
                        elif type(ref) == SimMemRead:
                            if irsb in self._ddg._ddg and stmt_id in self._ddg._ddg[irsb]:
                                dependent_run, dependent_stmt_id = self._ddg._ddg[irsb][stmt_id]
                                if type(dependent_run) == SimIRSB:
                                    # It's incorrect to do this:
                                    # 'run_statements[dependent_run].add(dependent_stmt_id)'
                                    # We should add a dependency to that SimRun object, and reanalyze
                                    # it by putting it to our worklist once more

                                    # Check if we need to reanalyze that block
                                    new_data_taint_set = set()
                                    new_data_taint_set.add(dependent_stmt_id)
                                    new_ts = TaintSource(dependent_run, -1,
                                        new_data_taint_set, set(), set())
                                    tmp_worklist.add(new_ts)
                                    l.debug("%s added to temp worklist.", dependent_run)
                                else:
                                    new_data_taint_set = set([-1])
                                    new_ts = TaintSource(dependent_run, -1, new_data_taint_set, \
                                                        set(), set())
                                    tmp_worklist.add(new_ts)
                                    l.debug("%s added to temp worklist.", dependent_run)
                        elif type(ref) == SimMemWrite:
                            if stmt_id in data_taint_set:
                                data_taint_set.remove(stmt_id)
                                run_statements[irsb].add(stmt_id)
                                for d in ref.data_reg_deps:
                                    reg_taint_set.add(d)
                                for d in ref.addr_reg_deps:
                                    reg_taint_set.add(d)
                                for d in ref.data_tmp_deps:
                                    tmp_taint_set.add(d)
                                for d in ref.addr_tmp_deps:
                                    tmp_taint_set.add(d)
                                # TODO: How do we handle other data dependencies here? Or if there is any?
                        elif type(ref) == SimCodeRef:
                            # l.debug("Ignoring SimCodeRef")
                            pass
                        else:
                            raise Exception("%s is not supported." % type(ref))
            elif isinstance(ts.run, SimProcedure):
                sim_proc = ts.run
                refs_dict = sim_proc.refs()
                l.debug("SimProcedure Refs:")
                l.debug(refs_dict)
                refs = []
                for k, v in refs_dict.items():
                    refs.extend(v)
                for ref in refs:
                    if type(ref) == SimRegWrite:
                        if ref.offset in reg_taint_set:
                            if ref.offset != simuvex.Architectures[arch_name].ip_offset:
                                # Remove this taint
                                reg_taint_set.remove(ref.offset)
                            # Taint all its dependencies
                            for reg_dep in ref.data_reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in ref.data_tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    elif type(ref) == SimTmpWrite:
                        if ref.tmp in tmp_taint_set:
                            # Remove this taint
                            tmp_taint_set.remove(ref.tmp)
                            # Taint all its dependencies
                            for reg_dep in ref.data_reg_deps:
                                reg_taint_set.add(reg_dep)
                            for tmp_dep in ref.data_tmp_deps:
                                tmp_taint_set.add(tmp_dep)
                    elif type(ref) == SimRegRead:
                        # Adding new ref!
                        reg_taint_set.add(ref.offset)
                    elif type(ref) == SimTmpRead:
                        l.debug("Ignoring SimTmpRead")
                    elif type(ref) == SimMemRef:
                        l.debug("Ignoring SimMemRef")
                    elif type(ref) == SimMemRead:
                        if sim_proc in self._ddg._ddg:
                            dependent_run, dependent_stmt_id = self._ddg._ddg[sim_proc][-1]
                            if type(dependent_run) == SimIRSB:
                                data_set = set()
                                data_set.add(dependent_stmt_id)
                                new_ts = TaintSource(dependent_run, -1, data_set, set(), set())
                                tmp_worklist.add(new_ts)
                                l.debug("%s added to temp worklist." % dependent_run)
                            else:
                                raise Exception("Not implemented.")
                    elif type(ref) == SimMemWrite:
                        if -1 in data_taint_set:
                            for d in ref.data_reg_deps:
                                reg_taint_set.add(d)
                            for d in ref.addr_reg_deps:
                                reg_taint_set.add(d)
                            for d in ref.data_tmp_deps:
                                tmp_taint_set.add(d)
                            for d in ref.addr_tmp_deps:
                                tmp_taint_set.add(d)
                            # TODO: How do we handle other data dependencies here? Or if there is any?
                    elif type(ref) == SimCodeRef:
                        l.debug("Ignoring SimCodeRef")
                    else:
                        raise Exception("%s is not supported." % type(ref))
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

                    l.debug("%s Got new predecessor %s" % (ts.run, p))
                    new_ts = TaintSource(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set, kids=list(kids_set))
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
                if isinstance(p, SimIRSB):
                    # Search for the last branching exit, just like
                    #     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
                    # , and then taint the temp variable inside if predicate
                    statement_ids = range(len(p.statements))
                    statement_ids.reverse()
                    cmp_stmt_id = 0
                    for stmt_id in statement_ids:
                        refs = p.statements[stmt_id].refs
                        # Ugly implementation here
                        has_code_ref = False
                        for r in refs:
                            if isinstance(r, SimCodeRef):
                                has_code_ref = True
                        if has_code_ref:
                            tmp_ref = refs[0]
                            new_tmp_taint_set.add(tmp_ref.tmp)
                            cmp_stmt_id = stmt_id
                            break

                run_statements[p].add(cmp_stmt_id)
                l.debug("%s Got new control-dependency predecessor %s" % (ts.run, p))
                new_ts = TaintSource(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set, kids=list(kids_set))
                tmp_worklist.add(new_ts)
                # Add it to our map
                self.runs_in_slice.add_edge(p, ts.run)

            # Merge temp worklist with the real worklist
            for taint_source in tmp_worklist.items():
                # Merge it with existing items in processed_ts
                existing_tses = filter(lambda r : r.run == taint_source.run, processed_ts)
                if len(existing_tses) > 0:
                    existing_ts = existing_tses[0]
                    if existing_ts.reg_taints >= taint_source.reg_taints and \
                            existing_ts.data_taints >= taint_source.data_taints and \
                            existing_ts.tmp_taints >= taint_source.tmp_taints:
                        l.debug("Ignore predecessor %s" % taint_source.run)
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

class TaintSource(object):
    # taints: a set of all tainted stuff after this basic block
    def __init__(self, run, stmt_id, data_taints, reg_taints, tmp_taints, kids=[]):
        self.run = run
        self.stmt_id = stmt_id
        self.data_taints = data_taints
        self.reg_taints = reg_taints
        self.tmp_taints = tmp_taints
        self.kids = kids

    def equalsTo(self, obj):
        return (self.irsb == obj.irsb) and (self.stmt_id == obj.stmt_id) and (self.taints == obj.taints)
