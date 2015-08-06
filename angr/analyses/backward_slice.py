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

class TaintSet(object):
    def __init__(self, run, stmt_id, data_taints, reg_taints, tmp_taints, taints_waitinglist=None, kids=None,
                 parent=None):
        """
        Describes a set of all taints at the end of a SimRun. TaintSet instances are put into a worklist in our
        taint-tracking algorithm.

        :param run: The related SimRun
        :param stmt_id: ID of the he last statement that we care about. -1 stands for the very last statement of a basic
                        block.
        :param data_taints: A list of memory taints
        :param reg_taints: A list of register taints
        :param tmp_taints: A list of temporary variable taints
        :param taints_waitinglist:
        :param kids:
        :param parent:
        """
        kids = kids or [ ]
        taints_waitinglist = taints_waitinglist or {}

        self.run = run
        self.stmt_id = stmt_id
        self.data_taints = data_taints
        self.reg_taints = reg_taints
        self.tmp_taints = tmp_taints
        self.taints_waitinglist = taints_waitinglist
        self.kids = kids
        self.parent = parent

    def __repr__(self):
        return "<TaintSet mem:%s, reg:%s, tmp:%s>" % (self.data_taints, self.reg_taints, self.tmp_taints)

class Taint(object):
    def __init__(self, type, addr=None, stmt_id=None, reg=None, tmp=None, mem_addr=None, value=None):
        """
        Describes a taint.

        :param type: The type can be one of the following values: reg, tmp, mem, or const
        :param addr: Address where this taint is created
        :param stmt_id: ID of the statement where this taint is created
        :param reg: Register offset
        :param tmp: ID of the temporary variable
        :param mem_addr: Address in memory
        :param value: Other values. e.g. value of the constant
        """

        if type not in ('reg', 'tmp', 'mem', 'const', 'exit'):
            raise AngrBackwardSlicingError('Unsupported taint type "%s"' % type)

        self.type = type
        self.addr = addr
        self.stmt_id = stmt_id

        # TODO: More sanity checks
        self.reg = reg
        self.tmp = tmp
        self.mem_addr = mem_addr
        self.value = value

    def __eq__(self, other):
        if self.type == 'exit':
            return self.addr == other.addr and self.stmt_id == other.stmt_id
        if self.type == 'mem':
            mem_addr_equal = hash(self.mem_addr.model) == hash(other.mem_addr.model) if self.mem_addr.symbolic else \
                self.mem_addr.model == other.mem_addr.model

            return mem_addr_equal and self.type == other.type and self.addr == other.addr \
                    and self.stmt_id == other.stmt_id
        else:
            return self.type == other.type and self.addr == other.addr \
                   and self.stmt_id == other.stmt_id and self._data == other._data

    def __hash__(self):
        if self.type == 'exit':
            return hash((self.addr, self.stmt_id))
        if self.type == 'mem' and self.mem_addr.symbolic:
            h = hash(self.type + "_" + str(hash(self.mem_addr.model)) + "_" + str(self.addr) + "_" + str(self.stmt_id))
        else:
            h = hash(self.type + "_" + str(self._data) + "_" + str(self.addr) + "_" + str(self.stmt_id))
        return h

    def copy(self):
        return Taint(self.type,
                     addr=self.addr,
                     stmt_id=self.stmt_id,
                     reg=self.reg,
                     tmp=self.tmp,
                     mem_addr=self.mem_addr,
                     value=self.value)

    @property
    def _data(self):
        if self.type == 'exit':
            data = None
        elif self.type == 'reg':
            data = self.reg
        elif self.type == 'tmp':
            data = self.tmp
        elif self.type == 'mem':
            data = self.mem_addr
        else:
            data = self.value

        return data

    def __repr__(self):
        if self.type == 'exit':
            s = "Taint<%s>(%s:%s)" % (self.type, hex(self.addr), self.stmt_id)
        else:
            s = "Taint<%s %s>(%s:%s)" % (self.type, self._data, hex(self.addr) if self.addr else self.addr, self.stmt_id)
        return s

class DataTaint(object):
    def __init__(self, simrun_addr, stmt_idx, address=None, bits=None):
        """
        Descriptor for tainted memory addresses and/or the statement that introduces this taint. It is put into
        data_taint_set during the worklist
        """

        self.simrun_addr = simrun_addr
        self.stmt_idx = stmt_idx
        self.address = address
        self.bits = bits

    @property
    def has_address(self):
        """
        Is this data taint descriptor related to some address?

        :return: True/False
        """
        return (self.address is not None)

    def __repr__(self):
        if not self.address:
            return "<DataTaint stmt %s:%d>" % (hex(self.simrun_addr), self.stmt_idx)
        else:
            return "<DataTaint stmt %s:%d addr %s[%d]>" % (
                hex(self.simrun_addr),
                self.stmt_idx,
                self.address,
                self.bits.ast
            )

    def __eq__(self, other):
        if not self.has_address:
            return self.simrun_addr == other.simrun_addr and self.stmt_idx == other.stmt_idx

        else:
            return self.address == other.address and self.bits == other.bits

    def __hash__(self):
        if not self.has_address:
            return hash((self.simrun_addr, self.stmt_idx))

        else:
            return hash((self.address, self.bits))

class BackwardSlice(Analysis):

    def __init__(self, cfg, cdg, ddg, irsb, stmt_id,
                 control_flow_slice=False,
                 no_construct=False):
        '''

        :param cfg:
        :param cdg:
        :param ddg:
        :param irsb:
        :param stmt_id:
        :param control_flow_slice:
        :param no_construct:            Only used for testing and debugging to easily create a BackwardSlice object
        :return:
        '''
        self._project = self._p
        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._target_irsb = irsb
        self._target_stmt_idx = stmt_id

        # Save a list of taints to beginwwith at the beginning of each SimRun
        self.initial_taints_per_run = None
        self.runs_in_slice = None
        self.run_statements = None

        if not no_construct:
            self._construct(irsb, stmt_id, control_flow_slice=control_flow_slice)

    def annotated_cfg(self, start_point=None):
        '''
        Returns an AnnotatedCFG based on slicing result.
        '''

        target_irsb_addr = self._target_irsb.addr
        target_stmt = self._target_stmt_idx
        start_point = start_point if start_point is not None else self._p.entry

        l.debug("Initializing AnnoCFG...")
        target_irsb = self._cfg.get_any_node(target_irsb_addr)
        anno_cfg = AnnotatedCFG(self._project, self._cfg, target_irsb_addr)
        if target_stmt is not -1:
            anno_cfg.set_last_stmt(target_irsb, target_stmt)

        #start_point_addr = 0
        #successors = [self._cfg.get_any_node(start_point)]
        #processed_successors = set()
        #while len(successors) > 0:

        for n in self._cfg.graph.nodes():
            run = n

            if run in self.run_statements:
                if self.run_statements[run] is True:
                    anno_cfg.add_simrun_to_whitelist(run)
                else:
                    anno_cfg.add_statements_to_whitelist(run, self.run_statements[run])

        for src, dst in self._cfg.graph.edges():

            run = src

            if dst in self.run_statements and src in self.run_statements:
                anno_cfg.add_exit_to_whitelist(run, dst)

            # TODO: expose here, maybe?
            #anno_cfg.set_path_merge_points(self._path_merge_points)

        return anno_cfg

    def is_taint_ip_related(self, simrun_addr, stmt_idx, taint_type, simrun_whitelist=None):
        """
        Query in taint graph to check if a specific taint will taint the IP in the future or not.
        The taint is specified with the tuple (simrun_addr, stmt_idx, taint_type).

        :param simrun_addr: Address of the SimRun
        :param stmt_idx: Statement ID
        :param taint_type: Type of the taint, might be one of the following: 'reg', 'tmp', 'mem'
        :param simrun_whitelist: A list of SimRun addresses that are whitelisted, i.e. the tainted exit will be ignored
                                if it is in those SimRuns
        :return: True/False
        """

        if simrun_whitelist is None:
            simrun_whitelist = set()
        if type(simrun_whitelist) is not set:
            simrun_whitelist = set(simrun_whitelist)

        # Find the specific taint in our graph
        taint = None
        for n in self.taint_graph.nodes():
            if n.type == taint_type and n.addr == simrun_addr and n.stmt_id == stmt_idx:
                taint = n
                break

        if taint is None:
            raise AngrBackwardSlicingError('The specific taint is not found')

        bfs_tree = networkx.bfs_tree(self.taint_graph, taint)

        # A node is tainting the IP if one of the following criteria holds:
        # - a descendant tmp variable is used as a default exit or a conditional exit of its corresponding SimRun
        # - a descendant register is the IP itself

        for descendant in bfs_tree.nodes():
            if descendant.type == 'exit':
                if descendant.addr not in simrun_whitelist:
                    return True
            elif descendant.type == 'reg' and descendant.reg == self._p.arch.ip_offset:
                return True

        return False

    def is_taint_impacting_stack_pointers(self, simrun_addr, stmt_idx, taint_type, simrun_whitelist=None):
        """
        Query in taint graph to check if a specific taint will taint the stack pointer in the future or not.
        The taint is specified with the tuple (simrun_addr, stmt_idx, taint_type).

        :param simrun_addr: Address of the SimRun
        :param stmt_idx: Statement ID
        :param taint_type: Type of the taint, might be one of the following: 'reg', 'tmp', 'mem'
        :param simrun_whitelist: A list of SimRun addresses that are whitelisted
        :return: True/False
        """

        if simrun_whitelist is None:
            simrun_whitelist = set()
        if type(simrun_whitelist) is not set:
            simrun_whitelist = set(simrun_whitelist)

        # Find the specific taint in our graph
        taint = None
        for n in self.taint_graph.nodes():
            if n.type == taint_type and n.addr == simrun_addr and n.stmt_id == stmt_idx:
                taint = n
                break

        if taint is None:
            raise AngrBackwardSlicingError('The specific taint is not found')

        bfs_tree = networkx.bfs_tree(self.taint_graph, taint)

        # A node is tainting the stack pointer if one of the following criteria holds:
        # - a descendant register is the sp/bp itself

        for descendant in bfs_tree.nodes():
            if descendant.type == 'reg' and (
                        descendant.reg in (self._p.arch.sp_offset, self._p.arch.bp_offset)
            ):
                return True

        return False

    #
    # Private methods
    #

    def _construct(self, sim_run, stmt_id, control_flow_slice=False):
        """
        Construct a dependency graph based on given parameters.

        :param sim_run: The SimRun instance where the backward slice should start from
        :param stmt_id: The statement ID where the backward slice starts from in the target SimRun instance. -1 for
                        starting from the very last statement
        :param control_flow_slice: Is the backward slicing only depends on CFG or not
        :return: None
        """

        if control_flow_slice:
            self._construct_control_flow_slice(sim_run)

        else:
            self._construct_default(sim_run, stmt_id)

    def _construct_control_flow_slice(self, irsb):
        """
        Build a slice of the program without considering the effect of data dependencies.
        This ia an incorrect hack, but it should work fine with small programs.

        :param irsb: The target IRSB. You probably wanna get it from the CFG somehow. It
                    must exist in the CFG.
        :return: None
        """

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

    def _construct_default(self, cfg_node, stmt_id):
        """
        Create a backward slice from a specific statement in a specific sim_run. It's based on a worklist algorithm.

        :param cfg_node: The CFGNode instance where the backward slice starts. It must be in the CFG
        :param stmt_id: ID of the target statement where the backward slice starts
        :return: None
        """

        self.taint_graph = networkx.DiGraph()

        if cfg_node not in self._cfg.graph:
            raise AngrBackwardSlicingError('Target SimRun (%s) is not in the CFG.', cfg_node)

        if stmt_id == -1:
            # Its jump target is tainted
            data_reg_deps = set()
            data_tmp_deps = set()

            # The tmp variable that irsb.next relies on will be tainted later

        else:
            path = self._project.factory.path(irsb.initial_state)
            s = path.state
            actions = filter(lambda r: r.type == 'reg' and r.action == 'write' and r.stmt_idx == stmt_id,
                          s.log.actions)
            if len(actions) != 1:
                raise Exception("Invalid references. len(actions) == %d." % len(actions))
            data_reg_deps = set(actions[0].data.reg_deps)
            data_tmp_deps = set(actions[0].data.tmp_deps)

        # TODO: Make it more elegant
        data_deps = set()
        # TODO: What's the data dependency here?

        start = TaintSet(cfg_node, stmt_id, data_deps, data_reg_deps, data_tmp_deps, taints_waitinglist={ }, kids=[ ])

        worklist = WorkList()
        worklist.add(start)
        processed_ts = set()
        self.initial_taints_per_run = defaultdict(list)
        self.runs_in_slice = networkx.DiGraph()
        # We are using a list here, and later on we reconstruct lists and write it to
        # self.run_statements
        self.run_statements = defaultdict(set)

        while worklist.size() > 0:

            ts = worklist.pop()

            # Initialize a temporary worklist
            temp_worklist = WorkList()

            # The current SimRun we are dealing with in this iteration
            try:
                current_run = self._p.factory.sim_run(ts.run.input_state)
            except simuvex.SimIRSBError:
                continue

            # Make a copy of all taint sets
            data_taint_set = ts.data_taints.copy()
            reg_taint_set = ts.reg_taints.copy()
            tmp_taint_set = ts.tmp_taints.copy()

            # A waiting list of all taints that are yet to be added onto the taint graph
            taints_waitinglist = ts.taints_waitinglist

            l.debug("Pick a new SimRun %s", current_run)

            if isinstance(current_run, simuvex.SimIRSB):
                current_run_type = 'irsb'

            elif isinstance(current_run, simuvex.SimProcedure):
                current_run_type = 'simproc'


            else:
                raise Exception("Unsupported SimRun type %s" % type(ts.run))

            state = None
            # We pick the state that has the most SimActions
            # TODO: Maybe we should always pick the one that is the default exit?
            max_count = 0
            successors = current_run.successors if current_run.successors else current_run.unsat_successors
            for s in successors:
                actions = list(s.log.actions)
                if len(actions) > max_count:
                    max_count = len(actions)
                    state = s

            if state is None:
                continue

            # We always taint the IP, otherwise Slicecutor cannot execute the generated slice
            reg_taint_set.add(self._project.arch.ip_offset)

            # Traverse the the current SimRun, and taint everything related

            # Now we don't have to taint the default exit anymore since Yan is kind enough to provide a SimExitAction!
            """
            # Taint the default exit first
            for action in current_run.next_expr.actions:
                if action.type == "tmp" and action.action == "read":
                    tmp_taint_set.add(action.tmp)
            """

            # However, we have to taint all exits other than the default one, otherwise the corresponding exit will be
            # missing in the final slice
            if current_run_type == 'irsb':
                all_exit_stmts = [ (i, stmt) for (i, stmt) in enumerate(current_run.irsb.statements)
                                   if isinstance(stmt, pyvex.IRStmt.Exit) ]
            else:
                all_exit_stmts = [ ]

            for i, exit_stmt in all_exit_stmts:
                tmp_taint_set.add(exit_stmt.guard.tmp)
                self.run_statements[ts.run].add(i)

            # We also taint the stack pointer, so we could keep the stack balanced
            reg_taint_set.add(self._project.arch.sp_offset)

            stmt_start_id = ts.stmt_id
            if stmt_start_id == -1:
                actions = reversed(list(state.log.actions))
            else:
                actions = reversed([a for a in state.log.actions if a.stmt_idx <= stmt_start_id])

            # Taint the tmp variable that irsb.next relies on
            if stmt_start_id == -1:
                # Get the basic block
                # TODO: Make sure we are working on an IRSB, not a SimProcedure
                # TODO: Get opt_level from state options
                pyvex_irsb = self._p.factory.block(addr=current_run.addr, opt_level=1)
                irsb_next = pyvex_irsb.vex.next

                if type(irsb_next) is pyvex.IRExpr.RdTmp:
                    tmp_taint_set.add(irsb_next.tmp)

            # Group those actions from the same statement together
            statement_actions = defaultdict(list)
            for action in actions:
                statement_actions[action.stmt_idx].append(action)

            all_stmt_idx = sorted(statement_actions.keys(), reverse=True)

            for stmt_idx in all_stmt_idx:

                # For every statement, the mem read action is taken and its corresponding addresses are labeled as
                # tainted if its tmp_deps/reg_deps are tainted *locally (e.g. in current statement)*. In this way,
                # we don't lose the link between a tmp write and a mem read.
                #
                # For example, the following statement
                #   t16 = LDle:I32(t14)
                # creates three SimActions:
                # - a reg read, reading from t14
                # - a mem read, reading from *t14
                # - a tmp write, writing to t16
                # The connection between the tmp write and the mem read is currently missing in SimActions. The only
                # way to handle it correctly is to taint everything in this statement immediately after we see a
                # tmp write to a tainted temp variable occurs.

                all_actions = statement_actions[stmt_idx]

                # All tainted registers and temp variables in current statement
                local_reg_taint_records = set()
                local_tmp_taint_records = set()

                for action in all_actions:

                    if not hasattr(action, 'action'):
                        # SimExitAction
                        handler_name = '_handle_%s' % action.type

                    else:
                        handler_name = "_handle_%s_%s" % (action.type, action.action)

                    if hasattr(self, handler_name):
                        action_taken = False

                        if action.type == 'mem' and action.action == 'read':
                            # Whether taking the mem read or not depends on whether it relies on registers/tmps
                            # that are tainted locally.
                            if (action.tmp_deps.issubset(local_tmp_taint_records) and
                                    action.reg_deps.issubset(local_reg_taint_records)):
                                handler = getattr(self, handler_name)
                                action_taken = handler(action, tmp_taint_set, reg_taint_set, data_taint_set, taints_waitinglist,
                                                        temp_worklist, ts.run, current_run, action.stmt_idx)

                        else:
                            handler = getattr(self, handler_name)
                            action_taken = handler(action, tmp_taint_set, reg_taint_set, data_taint_set, taints_waitinglist,
                                                temp_worklist, ts.run, current_run, action.stmt_idx)

                        if action_taken:
                            for r in action.reg_deps:
                                local_reg_taint_records.add(r)
                            for t in action.tmp_deps:
                                local_tmp_taint_records.add(t)

            # We create the TaintSource object using the old taints from ts, not the new ones
            # (tmp_taint_set, reg_taint_set, and data_taint_set). Then TS object is put into
            # processed_ts.
            new_taint_set = TaintSet(ts.run, -1, ts.data_taints, ts.reg_taints, ts.tmp_taints,
                                      taints_waitinglist=taints_waitinglist, kids=ts.kids)
            processed_ts.add(new_taint_set)

            # Filter all tainted registers
            has_reg_taints = False
            if len(reg_taint_set - ignored_registers[self._p.arch.name]) > 0:
                has_reg_taints = True

            # In the end, add this taint set to our list
            initial_taint_set = TaintSet(ts.run, -1, data_taint_set.copy(), reg_taint_set.copy(), tmp_taint_set.copy())
            self.initial_taints_per_run[ts.run].append(initial_taint_set)

            if len(data_taint_set) > 0 or has_reg_taints:
                # Get its predecessors from our CFG
                predecessors = self._cfg.get_predecessors(ts.run)
                for p in predecessors:
                    new_reg_taint_set = reg_taint_set.copy()
                    new_data_taint_set = data_taint_set.copy()
                    new_tmp_taint_set = tmp_taint_set.copy()
                    kids_set = set()

                    if self._p.is_hooked(p.addr):
                        irsb_ = self._cfg.irsb_from_node(p)
                        # If it's not a boring exit from its predecessor, we shall
                        # search for the last branching, and taint the temp variable
                        # there.
                        flat_successors = irsb_.flat_successors
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
                            if len(successors) == 0 or not self._p.factory.sim_run(successors[0]).default_exit:
                                # It might be 0 sometimes...
                                # Search for the last branching exit, just like
                                #     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
                                # , and then taint the temp variable inside if predicate
                                cmp_stmt_id, cmp_tmp_id = self._last_branching_statement(p.statements)
                                if cmp_stmt_id is not None:
                                    new_tmp_taint_set.add(cmp_tmp_id)
                                    self.run_statements[p].add(cmp_stmt_id)

                    l.debug("%s Got new predecessor %s", ts.run, p)
                    new_ts = TaintSet(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set,
                                      taints_waitinglist=taints_waitinglist.copy(), kids=list(kids_set), parent=ts.run)
                    temp_worklist.add(new_ts)
                    # Add it to our map
                    self.runs_in_slice.add_edge(p, ts.run)

            # Let's also search for predecessors on control dependency graph
            cdg_predecessors = self._cdg.get_predecessors(ts.run) if self._cdg is not None else [ ]
            for p in cdg_predecessors:
                new_reg_taint_set = reg_taint_set.copy()
                new_data_taint_set = data_taint_set.copy()
                new_tmp_taint_set = set()
                kids_set = set()
                if self._p.is_hooked(p.addr):
                    # Search for the last branching exit, just like
                    #     if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
                    # , and then taint the temp variable inside if predicate
                    irsb_ = self._cfg.irsb_from_node(p.run)
                    cmp_stmt_id, cmp_tmp_id = self._last_branching_statement(irsb_.statements)
                    if cmp_stmt_id is not None:
                        new_tmp_taint_set.add(cmp_tmp_id)
                        self.run_statements[p].add(cmp_stmt_id)

                l.debug("%s Got new control-dependency predecessor %s", ts.run, p)
                new_ts = TaintSet(p, -1, new_data_taint_set, new_reg_taint_set, new_tmp_taint_set,
                                  taints_waitinglist=taints_waitinglist.copy(), kids=list(kids_set))
                temp_worklist.add(new_ts)
                # Add it to our map
                self.runs_in_slice.add_edge(p, ts.run)

            # Merge temp worklist with the real worklist
            for taint_set in temp_worklist.items():
                # Merge it with existing items in processed_ts
                existing_tses = filter(lambda r : r.run == taint_set.run, processed_ts) #pylint:disable=W0640
                if len(existing_tses) > 0:
                    existing_ts = existing_tses[0]
                    if (existing_ts.reg_taints >= taint_set.reg_taints and
                             # existing_ts.data_taints >= taint_set.data_taints and
                            existing_ts.tmp_taints >= taint_set.tmp_taints):
                        l.debug("Ignore predecessor %s", taint_set.run)
                        continue
                    else:
                        # Remove the existing one
                        processed_ts.remove(existing_ts)
                        # Merge the old taint sets into new taint sets
                        taint_set.reg_taints |= existing_ts.reg_taints
                        taint_set.data_taints |= existing_ts.data_taints
                        taint_set.tmp_taints |= existing_ts.tmp_taints

                l.debug("%s added to real worklist.", taint_set.run)
                # Add it into the real worklist
                worklist.add(taint_set)

        # Reconstruct the run_statements
        _run_statements = self.run_statements
        self.run_statements = defaultdict(list)
        for cfg_node, s in _run_statements.items():
            self.run_statements[cfg_node] = list(s)

    #
    # All handlers
    #

    def _handle_exit(self, action, tmp_taint_set, reg_taint_set, data_taint_set,
                          taints_waitinglist, temp_worklist, cfg_node, current_run, stmt_idx):
        """
        Slicing handler for register writes

        :param action: The SimAction instance
        :param tmp_taint_set: A set of all tainted temp variable indices
        :param reg_taint_set: A set of all tainted register offsets
        :param data_taint_set: A set of all tainted memory addresses
        :param taints_waitinglist:
        ;param temp_worklist: The temporary worklist
        :param cfg_node: The CFG node
        :param current_run: Current SimRun instance
        :param stmt_idx: Statement ID. -1 for SimProcedures
        :return: True/False, indicating whether the corresponding statement is taken or not
        """

        # The exit is always tainted

        for tmp_dep in action.tmp_deps:
            tmp_taint_set.add(tmp_dep)
            # Create a new tmp taint, and put it into the waiting list
            taint = Taint('tmp', tmp=tmp_dep)
            taints_waitinglist[taint] = Taint('exit', addr=current_run.addr, stmt_id=stmt_idx)

        return True

    def _handle_reg_write(self, action, tmp_taint_set, reg_taint_set, data_taint_set,
                          taints_waitinglist, temp_worklist, cfg_node, current_run, stmt_idx):
        """
        Slicing handler for register writes

        :param action: The SimAction instance
        :param tmp_taint_set: A set of all tainted temp variable indices
        :param reg_taint_set: A set of all tainted register offsets
        :param data_taint_set: A set of all tainted memory addresses
        :param taints_waitinglist:
        ;param temp_worklist: The temporary worklist
        :param cfg_node: The CFG node
        :param current_run: Current SimRun instance
        :param stmt_idx: Statement ID. -1 for SimProcedures
        :return: True/False, indicating whether the corresponding statement is taken or not
        """

        reg_offset = action.offset

        if reg_offset not in reg_taint_set:
            return False

        else:
            self.run_statements[cfg_node].add(stmt_idx)

            # Add all taint links onto our taint graph
            waiting_taints = [ (s, d) for s, d in taints_waitinglist.iteritems()
                         if s.type == 'reg' and s.reg == reg_offset ]
            for src, dst in waiting_taints:
                del taints_waitinglist[src]

                src = src.copy()
                src.addr = current_run.addr
                src.stmt_id = stmt_idx
                self.taint_graph.add_edge(src, dst)

            if action.offset != self._project.arch.ip_offset:
                # Remove this taint
                reg_taint_set.remove(reg_offset)

            # Taint all its dependencies
            for reg_dep in action.data.reg_deps:
                reg_taint_set.add(reg_dep)
                # Create a new reg taint, and put it into the waiting list
                taint = Taint('reg', reg=reg_dep)
                taints_waitinglist[taint] = Taint('reg', addr=current_run.addr, stmt_id=stmt_idx, reg=reg_offset)

            for tmp_dep in action.data.tmp_deps:
                tmp_taint_set.add(tmp_dep)
                # Create a new tmp taint, and put it into the waiting list
                taint = Taint('tmp', tmp=tmp_dep)
                taints_waitinglist[taint] = Taint('reg', addr=current_run.addr, stmt_id=stmt_idx, reg=reg_offset)

            return True

    def _handle_tmp_write(self, action, tmp_taint_set, reg_taint_set, data_taint_set,
                          taints_waitinglist, temp_worklist, cfg_node, current_run, stmt_idx):
        """
        Slicing handler for temporary variable assignments

        :param action: The SimAction instance
        :param tmp_taint_set: A set of all tainted temp variable indices
        :param reg_taint_set: A set of all tainted register offsets
        :param data_taint_set: A set of all tainted memory addresses
        :param taints_waitinglist:
        ;param temp_worklist: The temporary worklist
        :param cfg_node: The CFG node
        :param current_run: Current SimRun instance
        :param stmt_idx: Statement ID. -1 for SimProcedures
        :return: True/False, indicating whether the corresponding statement is taken or not
        """

        tmp = action.tmp

        if tmp not in tmp_taint_set:
            return False

        else:
            self.run_statements[cfg_node].add(stmt_idx)

            # Retrieve all corresponding taints in the waiting list
            waiting_taints = [ (s, d) for s, d in taints_waitinglist.iteritems()
                               if s.type == 'tmp' and s.tmp == tmp ]
            for src, dst in waiting_taints:
                del taints_waitinglist[src]

                src = src.copy()
                src.addr = current_run.addr
                src.stmt_id = stmt_idx
                self.taint_graph.add_edge(src, dst)

            # Remove this taint
            tmp_taint_set.remove(tmp)

            # Taint all its dependencies
            for reg_dep in action.data.reg_deps:
                reg_taint_set.add(reg_dep)
                # Create a new reg taint, and put it onto the waiting list
                taint = Taint('reg', reg=reg_dep)
                taints_waitinglist[taint] = Taint('tmp', addr=current_run.addr, stmt_id=stmt_idx, tmp=tmp)

            for tmp_dep in action.data.tmp_deps:
                tmp_taint_set.add(tmp_dep)
                # Create a new tmp taint, and put it onto the waiting list
                taint = Taint('tmp', tmp=tmp_dep)
                taints_waitinglist[taint] = Taint('tmp', addr=current_run.addr, stmt_id=stmt_idx, tmp=tmp)

            # It might have a memory dependency
            # Take a look at the corresponding tmp
            stmt = current_run.statements[stmt_idx]
            mem_actions = [ a for a in stmt.actions if a.type == 'mem' and a.action == 'read' ]
            if mem_actions:
                mem_action = mem_actions[0]
                src = Taint(type="mem", addr=current_run.addr, stmt_id=stmt_idx, mem_addr=mem_action.addr.ast)
                dst = Taint(type="tmp", addr=current_run.addr, stmt_id=stmt_idx, tmp=tmp)
                self.taint_graph.add_edge(src, dst)

            return True

    def _handle_mem_read(self, action, tmp_taint_set, reg_taint_set, data_taint_set,
                         taints_waitinglist, temp_worklist, cfg_node, current_run, stmt_idx):
        """
        Slicing handler for memory reads

        :param action: The SimAction instance
        :param tmp_taint_set: A set of all tainted temp variable indices
        :param reg_taint_set: A set of all tainted register offsets
        :param data_taint_set: A set of all tainted memory addresses
        :param taints_waitinglist:
        ;param temp_worklist: The temporary worklist
        :param cfg_node: The CFG node
        :param current_run: Current SimRun instance
        :param stmt_idx: Statement ID. -1 for SimProcedures
        :return: True/False, indicating whether the corresponding statement is taken or not
        """

        # If this handler is called, this mem read action must be taken.

        if self._ddg is not None:

            # We rely on DDG if there is one available
            if (current_run.addr in self._ddg._graph and
                stmt_idx in self._ddg._graph[current_run.addr]):

                dependency_set = self._ddg._graph[current_run.addr][stmt_idx]

                for dependent_run_addr, dependent_stmt_id in dependency_set:
                    dependent_run = self._cfg.get_any_irsb(dependent_run_addr)
                    if isinstance(dependent_run, simuvex.SimIRSB):
                        # It's incorrect to do this:
                        # 'run_statements[dependent_run].add(dependent_stmt_id)'
                        # We should add a dependency to that SimRun object, and reanalyze
                        # it by putting it to our worklist once more

                        # Check if we need to reanalyze that block

                        data_taint = DataTaint(dependent_run.addr, dependent_stmt_id)

                        new_data_taint_set = set()
                        new_data_taint_set.add(data_taint)

                        dependent_runs = self._cfg.get_all_nodes(dependent_run_addr)
                        for d_run in dependent_runs:
                            new_ts = TaintSet(d_run, -1,
                                new_data_taint_set, set(), set())
                            temp_worklist.add(new_ts)
                            l.debug("%s added to temp worklist.", d_run)

                    else:
                        # A SimProcedure instance
                        data_taint = DataTaint(dependent_run.addr, -1)

                        new_data_taint_set = { data_taint }
                        dependent_runs = self._cfg.get_all_nodes(dependent_run_addr)
                        for d_run in dependent_runs:
                            new_ts = TaintSet(d_run, -1, new_data_taint_set,
                                            set(), set())
                            temp_worklist.add(new_ts)
                        l.debug("%s added to temp worklist.", dependent_run)

        else:
            # No DDG available. Let's log the address and size then

            data_taint = DataTaint(current_run.addr, stmt_idx, address=action.addr, bits=action.size)

            data_taint_set.add(data_taint)

            # Add all taint links onto our taint graph
            waiting_taints = [ (s, d) for s, d in taints_waitinglist.iteritems()
                         if s.type == 'mem' and (s.mem_addr == action.addr).model is True ] # TODO: mem_size
            for src, dst in waiting_taints:
                del taints_waitinglist[src]

                src = src.copy()
                src.addr = current_run.addr
                src.stmt_id = stmt_idx
                self.taint_graph.add_edge(src, dst)

            # Taint all its dependencies

            # for mem read, we should taint its source first
            taint = Taint('mem', mem_addr=action.addr.ast)
            taints_waitinglist[taint] = Taint('mem', addr=current_run.addr, stmt_id=stmt_idx, mem_addr=action.addr.ast) # TODO: mem_size

            for reg_dep in action.data.reg_deps:
                reg_taint_set.add(reg_dep)
                # Create a new reg taint, and put it into the waiting list
                taint = Taint('reg', reg=reg_dep)
                taints_waitinglist[taint] = Taint('mem', addr=current_run.addr, stmt_id=stmt_idx, mem_addr=action.addr.ast) # TODO: mem_size

            for tmp_dep in action.data.tmp_deps:
                tmp_taint_set.add(tmp_dep)
                # Create a new tmp taint, and put it into the waiting list
                taint = Taint('tmp', tmp=tmp_dep)
                taints_waitinglist[taint] = Taint('mem', addr=current_run.addr, stmt_id=stmt_idx, mem_addr=action.addr.ast) # TODO: mem_size

        return True

    def _handle_mem_write(self, action, tmp_taint_set, reg_taint_set, data_taint_set,
                          taints_waitinglist, temp_worklist, cfg_node, current_run, stmt_idx):
        """
        Slicing handler for memory writes

        :param action: The SimAction instance
        :param tmp_taint_set: A set of all tainted temp variable indices
        :param reg_taint_set: A set of all tainted register offsets
        :param data_taint_set: A set of all tainted memory addresses
        :param taints_waitinglist:
        ;param temp_worklist: The temporary worklist
        :param cfg_node: The CFG node
        :param current_run: Current SimRun instance
        :param stmt_idx: Statement ID. -1 for SimProcedures
        :return: True/False, indicating whether the corresponding statement is taken or not
        """

        if self._ddg is not None:
            # We can rely on the DDG
            data_taint = None
            for dt in data_taint_set:
                if dt.simrun_addr == current_run.addr and dt.stmt_idx == stmt_idx:
                    data_taint = dt
                    break

            if data_taint is not None:

                data_taint_set.remove(data_taint)

                self.run_statements[cfg_node].add(stmt_idx)

                for d in action.data.reg_deps:
                    reg_taint_set.add(d)
                for d in action.addr.reg_deps:
                    reg_taint_set.add(d)
                for d in action.data.tmp_deps:
                    tmp_taint_set.add(d)
                for d in action.addr.tmp_deps:
                    tmp_taint_set.add(d)
                # TODO: How do we handle other data dependencies here? Or if there is any?

                return True

            else:
                return False

        else:
            # DDG is not there...

            data_taint = None
            for dt in data_taint_set:
                if ((dt.address == action.addr).model is True # FIXME: This is ugly. claripy.is_true() is the way to go
                        and (dt.bits.ast == action.size.ast)):
                    data_taint = dt
                    break

            if data_taint is not None:

                data_taint_set.remove(data_taint)

                self.run_statements[cfg_node].add(stmt_idx)

                for d in action.data.reg_deps:
                    reg_taint_set.add(d)
                for d in action.addr.reg_deps:
                    reg_taint_set.add(d)
                for d in action.data.tmp_deps:
                    tmp_taint_set.add(d)
                for d in action.addr.tmp_deps:
                    tmp_taint_set.add(d)

                # Add all taint links onto our taint graph
                waiting_taints = [ (s, d) for s, d in taints_waitinglist.iteritems()
                             if s.type == 'mem' and (s.mem_addr == action.addr).model is True ] # TODO: mem_size
                for src, dst in waiting_taints:
                    del taints_waitinglist[src]

                    src = src.copy()
                    src.addr = current_run.addr
                    src.stmt_id = stmt_idx
                    self.taint_graph.add_edge(src, dst)

                # Taint all its dependencies
                for reg_dep in action.data.reg_deps:
                    reg_taint_set.add(reg_dep)
                    # Create a new reg taint, and put it into the waiting list
                    taint = Taint('reg', reg=reg_dep)
                    taints_waitinglist[taint] = Taint('mem', addr=current_run.addr, stmt_id=stmt_idx, mem_addr=action.addr.ast) # TODO: mem_size

                for tmp_dep in action.data.tmp_deps:
                    tmp_taint_set.add(tmp_dep)
                    # Create a new tmp taint, and put it into the waiting list
                    taint = Taint('tmp', tmp=tmp_dep)
                    taints_waitinglist[taint] = Taint('mem', addr=current_run.addr, stmt_id=stmt_idx, mem_addr=action.addr.ast) # TODO: mem_size

                return True

            else:
                return False

    #
    # Helper functions
    #

    @staticmethod
    def _last_branching_statement(statements):
        '''
        Search for the last branching exit, just like
        #   if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
        and then taint the temp variable inside if predicate
        '''
        cmp_stmt_id = None
        cmp_tmp_id = None
        all_statements = len(statements)
        statements = reversed(statements)
        for stmt_rev_idx, stmt in enumerate(statements):
            stmt_idx = all_statements - stmt_rev_idx - 1
            actions = stmt.actions
            # Ugly implementation here
            has_code_action = False
            for a in actions:
                if isinstance(a, simuvex.SimActionExit):
                    has_code_action = True
                    break
            if has_code_action:
                readtmp_action = next(ifilter(lambda r: r.type == 'tmp' and r.action == 'read', actions), None)
                if readtmp_action is not None:
                    cmp_tmp_id = readtmp_action.tmp
                    cmp_stmt_id = stmt_idx
                    break
                else:
                    raise AngrBackwardSlicingError("ReadTempAction is not found. Please report to Fish.")

        return cmp_stmt_id, cmp_tmp_id

import pyvex
import archinfo

from .cfg import CFGNode

#
# Ignored tainted registers. We assume those registers are not tainted, or we just don't care about them
#

# TODO: Add support for more architectures

def _regs_to_offsets(arch_name, regs):
    offsets = set()
    arch = archinfo.arch_from_id(arch_name)
    for r in regs:
        offsets.add(arch.registers[r][0])
    return offsets

_ignored_registers = {
    'X86': { 'esp', 'eip' },
    'AMD64': { 'rsp', 'rip', 'fs' }
}

ignored_registers = { }
for k, v in _ignored_registers.iteritems():
    ignored_registers[k] = _regs_to_offsets(k, v)
