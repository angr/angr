import logging
from collections import defaultdict
from itertools import ifilter

import networkx

import simuvex
import pyvex

from ..annocfg import AnnotatedCFG
from ..analysis import Analysis, register_analysis
from ..errors import AngrBackwardSlicingError
from .code_location import CodeLocation

l = logging.getLogger(name="angr.analyses.backward_slice")

class BackwardSlice(Analysis):
    """
    Represents a backward slice of the program.
    """

    def __init__(self, cfg, cdg, ddg,
                 targets=None,
                 cfg_node=None,
                 stmt_id=None,
                 control_flow_slice=False,
                 same_function=False,
                 no_construct=False):
        """
        Create a backward slice from a specific statement based on provided control flow graph (CFG), control
        dependence graph (CDG), and data dependence graph (DDG).

        The data dependence graph can be either CFG-based, or Value-set analysis based. A CFG-based DDG is much faster
        to generate, but it only reflects those states while generating the CFG, and it is neither sound nor accurate.
        The VSA based DDG (called VSA_DDG) is based on static analysis, which gives you a much better result.

        :param cfg:                 The control flow graph.
        :param cdg:                 The control dependence graph.
        :param ddg:                 The data dependence graph.
        :param targets:             A list of "target" that specify targets of the backward slices. Each target can be a
                                    tuple in form of (cfg_node, stmt_idx), or a CodeLocation instance.
        :param cfg_node:            Deprecated. The target CFGNode to reach. It should exist in the CFG.
        :param stmt_id:             Deprecated. The target statement to reach.
        :param control_flow_slice:  True/False, indicates whether we should slice only based on CFG. Sometimes when
                                    acquiring DDG is difficult or impossible, you can just create a slice on your CFG.
                                    Well, if you don't even have a CFG, then...
        :param no_construct:        Only used for testing and debugging to easily create a BackwardSlice object.
        """

        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._same_function = same_function

        # All targets
        self._targets = [ ]

        if cfg_node is not None or stmt_id is not None:
            l.warning('"cfg_node" and "stmt_id" are deprecated. Please use "targets" to pass in one or more targets.')

            self._targets = [ (cfg_node, stmt_id) ]

        if targets is not None:
            for t in targets:
                if isinstance(t, CodeLocation):
                    node = self._cfg.get_any_node(t.simrun_addr)
                    self._targets.append((node, t.stmt_idx))
                elif type(t) is tuple:
                    self._targets.append(t)
                else:
                    raise AngrBackwardSlicingError('Unsupported type of target %s' % t)

        # Save a list of taints to begin with at the beginning of each SimRun
        self.initial_taints_per_run = None
        self.runs_in_slice = None
        self.cfg_nodes_in_slice = None
        # IDs of all chosen statement for each SimRun
        self.chosen_statements = defaultdict(set)
        # IDs for all chosen exit statements as well as their corresponding targets
        self.chosen_exits = defaultdict(list)

        if not no_construct:
            self._construct(self._targets, control_flow_slice=control_flow_slice)

    #
    # Public methods
    #

    def __repr__(self):
        s = "BackwardSlice (to %s)" % self._targets
        return s

    def dbg_repr(self, max_display=10):
        """
        Debugging output of this slice.

        :param max_display: The maximum number of SimRun slices to show.
        :return:            A string representation.
        """

        s = repr(self) + "\n"

        if len(self.chosen_statements) > max_display:
            s += "%d SimRuns in program slice, displaying %d.\n" % (len(self.chosen_statements), max_display)
        else:
            s += "%d SimRuns in program slice.\n" % len(self.chosen_statements)

        # Pretty-print the first `max_display` basic blocks
        if max_display is None:
            # Output all
            run_addrs = sorted(self.chosen_statements.keys())

        else:
            # Only output the first "max_display" ones
            run_addrs = sorted(self.chosen_statements.keys())[ : max_display]

        for run_addr in run_addrs:
            s += self.dbg_repr_run(run_addr) + "\n"

        return s

    def dbg_repr_run(self, run_addr):
        """
        Debugging output of a single SimRun slice.

        :param run_addr:    Address of the SimRun.
        :return:            A string representation.
        """

        if self.project.is_hooked(run_addr):
            ss = "%#x Hooked\n" % run_addr

        else:
            ss = "%#x\n" % run_addr

            # statements
            chosen_statements = self.chosen_statements[run_addr]

            vex_block = self.project.factory.block(run_addr).vex

            statements = vex_block.statements
            for i in range(0, len(statements)):
                if i in chosen_statements:
                    line = "+"
                else:
                    line = "-"
                line += "[% 3d] " % i
                line += str(statements[i])
                ss += line + "\n"

            # exits
            targets = self.chosen_exits[run_addr]
            addr_strs = [ ]
            for exit_stmt_id, target_addr in targets:
                if target_addr is None:
                    addr_strs.append("default")
                else:
                    addr_strs.append("%#x" % target_addr)

            ss += "Chosen exits: " + ", ".join(addr_strs)

        return ss

    def annotated_cfg(self, start_point=None):
        """
        Returns an AnnotatedCFG based on slicing result.
        """

        # TODO: Support context-sensitivity

        targets = [ ]

        for simrun, stmt_idx in self._targets:
            targets.append((simrun.addr, stmt_idx))

        l.debug("Initializing AnnoCFG...")
        anno_cfg = AnnotatedCFG(self.project, self._cfg)

        for simrun, stmt_idx in self._targets:
            if stmt_idx is not -1:
                anno_cfg.set_last_statement(simrun.addr, stmt_idx)

        for n in self._cfg.graph.nodes():
            run = n

            if run.addr in self.chosen_statements:
                if self.chosen_statements[run.addr] is True:
                    anno_cfg.add_simrun_to_whitelist(run.addr)
                else:
                    anno_cfg.add_statements_to_whitelist(run.addr, self.chosen_statements[run.addr])

        for src, dst in self._cfg.graph.edges():
            run = src

            if dst.addr in self.chosen_statements and src.addr in self.chosen_statements:
                anno_cfg.add_exit_to_whitelist(run.addr, dst.addr)

        return anno_cfg

    def is_taint_related_to_ip(self, simrun_addr, stmt_idx, taint_type, simrun_whitelist=None):
        """
        Query in taint graph to check if a specific taint will taint the IP in the future or not.
        The taint is specified with the tuple (simrun_addr, stmt_idx, taint_type).

        :param simrun_addr:         Address of the SimRun.
        :param stmt_idx:            Statement ID.
        :param taint_type:          Type of the taint, might be one of the following: 'reg', 'tmp', 'mem'.
        :param simrun_whitelist:    A list of SimRun addresses that are whitelisted, i.e. the tainted exit will be
                                    ignored if it is in those SimRuns.
        :returns:                   True/False
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
            elif descendant.type == 'reg' and descendant.reg == self.project.arch.ip_offset:
                return True

        return False

    def is_taint_impacting_stack_pointers(self, simrun_addr, stmt_idx, taint_type, simrun_whitelist=None):
        """
        Query in taint graph to check if a specific taint will taint the stack pointer in the future or not.
        The taint is specified with the tuple (simrun_addr, stmt_idx, taint_type).

        :param simrun_addr:         Address of the SimRun.
        :param stmt_idx:            Statement ID.
        :param taint_type:          Type of the taint, might be one of the following: 'reg', 'tmp', 'mem'.
        :param simrun_whitelist:    A list of SimRun addresses that are whitelisted.
        :returns:                   True/False.
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
                        descendant.reg in (self.project.arch.sp_offset, self.project.arch.bp_offset)
            ):
                return True

        return False

    #
    # Private methods
    #

    def _construct(self, targets, control_flow_slice=False):
        """
        Construct a dependency graph based on given parameters.

        :param targets:             A list of tuples like (CFGNode, statement ID)
        :param control_flow_slice:  Is the backward slicing only depends on CFG or not.
        """

        if control_flow_slice:
            simruns = [ r for r, _ in targets ]
            self._construct_control_flow_slice(simruns)

        else:
            self._construct_default(targets)

    def _construct_control_flow_slice(self, simruns):
        """
        Build a slice of the program without considering the effect of data dependencies.
        This is an incorrect hack, but it should work fine with small programs.

        :param simruns: A list of SimRun targets. You probably wanna get it from the CFG somehow. It must exist in the
                        CFG.
        """

        # TODO: Support context-sensitivity!

        if self._cfg is None:
            l.error('Please build CFG first.')

        cfg = self._cfg.graph
        for simrun in simruns:
            if simrun not in cfg:
                l.error('SimRun instance %s is not in the CFG.', simrun)

        stack = [ ]
        for simrun in simruns:
            stack.append(simrun)

        self.runs_in_slice = networkx.DiGraph()
        self.cfg_nodes_in_slice = networkx.DiGraph()

        self.chosen_statements = { }
        while stack:
            # Pop one out
            block = stack.pop()
            if block.addr not in self.chosen_statements:
                self.chosen_statements[block.addr] = True
                # Get all predecessors of that block
                predecessors = cfg.predecessors(block)
                for pred in predecessors:
                    stack.append(pred)
                    self.cfg_nodes_in_slice.add_edge(pred, block)
                    self.runs_in_slice.add_edge(pred.addr, block.addr)

    def _construct_default(self, targets):
        """
        Create a backward slice from a specific statement in a specific sim_run. This is done by traverse the CFG
        backwards, and mark all tainted statements based on dependence graphs (CDG and DDG) provided initially. The
        traversal terminated when we reach the entry point, or when there is no unresolved dependencies.

        :param targets: A list of tuples like (cfg_node, stmt_idx), where cfg_node is a CFGNode instance where the
                        backward slice starts, and it must be included in CFG and CDG. stmt_idx is the ID of the target
                        statement where the backward slice starts.
        """

        # TODO: Support context-sensitivity

        l.debug("Constructing a default backward program slice")

        self.taint_graph = networkx.DiGraph()

        taints = set()
        accessed_taints = set()

        # Fill in the taint set

        for cfg_node, stmt_idx in targets:
            if cfg_node not in self._cfg.graph:
                raise AngrBackwardSlicingError('Target CFGNode %s is not in the CFG.' % cfg_node)

            if stmt_idx == -1:
                new_taints = self._handle_control_dependence(cfg_node)
                taints |= new_taints

            else:
                cl = CodeLocation(cfg_node.addr, stmt_idx)
                taints.add(cl)

        while taints:
            # Pop a tainted code location
            tainted_cl = taints.pop()

            l.debug("Checking taint %s...", tainted_cl)

            # Mark it as picked
            self._pick_statement(tainted_cl.simrun_addr, tainted_cl.stmt_idx)

            # Mark it as accessed
            accessed_taints.add(tainted_cl)

            # Pick all its data dependencies from data dependency graph
            if self._ddg is not None and tainted_cl in self._ddg:
                if isinstance(self._ddg, networkx.DiGraph):
                    predecessors = self._ddg.predecessors(tainted_cl)
                else:
                    # angr.analyses.DDG
                    predecessors = self._ddg.get_predecessors(tainted_cl)
                l.debug("Returned %d predecessors for %s from data dependence graph", len(predecessors), tainted_cl)

                for p in predecessors:
                    if p not in accessed_taints:
                        taints.add(p)

                    self.taint_graph.add_edge(p, tainted_cl)

            # Handle the control dependence
            for n in self._cfg.get_all_nodes(tainted_cl.simrun_addr):
                new_taints = self._handle_control_dependence(n)

                l.debug("Returned %d taints for %s from control dependence graph", len(new_taints), n)

                for taint in new_taints:
                    if taint not in accessed_taints:
                        taints.add(taint)

                    self.taint_graph.add_edge(taint, tainted_cl)

        # In the end, map the taint graph onto CFG
        self._map_to_cfg()

    def _find_exits(self, src_block, target_block):
        """
        Source block has more than one exit, and through some of those exits, the control flow can eventually go to
        the target block. This method returns exits that lead to the target block.

        :param src_block:       The block that has multiple exits.
        :param target_block:    The target block to reach.
        :returns: a dict of statement ID -> a list of target IPs (or None if the exit should not be taken), each
                corresponds to an exit to take in order to reach the target.
                For example, it returns the following dict:
                {
                    'default': None, # It has a default exit, but shouldn't be taken
                    15: [ 0x400080 ], # Statement 15 is an exit statement, and should be taken when the target is
                                      # 0x400080
                    28: None  # Statement 28 is an exit statement, but shouldn't be taken
                }
        """

        # Enumerate all statements and find exit statements
        # Since we don't have a state, we have to rely on the pyvex block instead of SimIRSB
        # Just create the block from pyvex again - not a big deal

        if self.project.is_hooked(src_block.addr):
            # Just return all exits for now
            return { -1: [ target_block.addr ] }

        block = self.project.factory.block(src_block.addr)
        vex_block = block.vex

        exit_stmt_ids = { }

        for stmt_idx, stmt in enumerate(vex_block.statements):
            if isinstance(stmt, pyvex.IRStmt.Exit):
                exit_stmt_ids[stmt_idx] = None

        # And of course, it has a default exit
        # Don't forget about it.
        exit_stmt_ids['default'] = None

        # Find all paths from src_block to target_block
        # FIXME: This is some crappy code written in a hurry. Replace the all_simple_paths() later.
        all_simple_paths = list(networkx.all_simple_paths(self._cfg.graph, src_block, target_block, cutoff=3))

        for simple_path in all_simple_paths:
            if len(simple_path) <= 1:
                # Oops, it looks that src_block and target_block are the same guy?
                continue

            if self._same_function:
                # Examine this path and make sure it does not have call or return edge
                for i in xrange(len(simple_path) - 1):
                    jumpkind = self._cfg.graph[simple_path[i]][simple_path[i + 1]]['jumpkind']
                    if jumpkind in ('Ijk_Call', 'Ijk_Ret'):
                        return {  }

            # Get the first two nodes
            a, b = simple_path[0], simple_path[1]
            # Get the exit statement ID from CFG
            exit_stmt_id = self._cfg.get_exit_stmt_idx(a, b)
            if exit_stmt_id is None:
                continue

            # Mark it!
            if exit_stmt_ids[exit_stmt_id] is None:
                exit_stmt_ids[exit_stmt_id] = [ b.addr ]
            else:
                exit_stmt_ids[exit_stmt_id].append(b.addr)

        return exit_stmt_ids

    def _handle_control_dependence(self, target_node):
        """
        Based on control dependence graph, pick all exits (statements) that lead to the target.

        :param target_node: A CFGNode instance.
        :returns:           A set of new tainted code locations.
        """

        new_taints = set()

        # Query the CDG and figure out all control flow transitions to reach this target
        cdg_guardians = self._cdg.get_guardians(target_node)
        if not cdg_guardians:
            # this block is directly reachable from the entry point
            pass

        else:
            # For each predecessor on CDG, find the correct exit to take, and continue slicing from those exits
            for predecessor in cdg_guardians:
                exits = self._find_exits(predecessor, target_node)

                for stmt_idx, target_addresses in exits.iteritems():
                    if stmt_idx is not None:
                        # If it's an exit statement, mark it as picked
                        self._pick_statement(predecessor.addr,
                                             self._normalize_stmt_idx(predecessor.addr, stmt_idx)
                                             )
                        # If it's the default statement, we should also pick other conditional exit statements
                        if stmt_idx == 'default':
                            conditional_exits = self._conditional_exits(predecessor.addr)
                            for conditional_exit_stmt_id in conditional_exits:
                                cl = CodeLocation(predecessor.addr,
                                                  self._normalize_stmt_idx(predecessor.addr, conditional_exit_stmt_id)
                                                  )
                                new_taints.add(cl)

                                self._pick_statement(predecessor.addr,
                                                     self._normalize_stmt_idx(predecessor.addr, conditional_exit_stmt_id)
                                                     )

                    if target_addresses is not None:

                        if stmt_idx is not None:
                            # If it's an exit statement, we create a new tainted code location
                            cl = CodeLocation(predecessor.addr,
                                              self._normalize_stmt_idx(predecessor.addr, stmt_idx)
                                              )
                            new_taints.add(cl)

                        # Mark those exits as picked
                        for target_address in target_addresses:
                            self._pick_exit(predecessor.addr, stmt_idx, target_address)

                    # On CFG, pick default exits of all nodes between predecessor and our target node
                    # Usually this is not required if basic blocks strictly end at control flow transitions. But this is
                    # not always the case for some architectures
                    all_simple_paths = list(networkx.all_simple_paths(self._cfg.graph, predecessor, target_node, cutoff=3))

                    previous_node = None
                    for path in all_simple_paths:
                        for node in path:
                            self._pick_statement(node.addr, self._normalize_stmt_idx(node.addr, 'default'))
                            if previous_node is not None:
                                self._pick_exit(previous_node.addr, 'default', node.addr)

        return new_taints

    def _map_to_cfg(self):
        """
        Map our current slice to CFG.

        Based on self._statements_per_run and self._exit_statements_per_run, this method will traverse the CFG and
        check if there is any missing block on the path. If there is, the default exit of that missing block will be
        included in the slice. This is because Slicecutor cannot skip individual basic blocks along a path.
        """

        exit_statements_per_run = self.chosen_exits
        new_exit_statements_per_run = defaultdict(list)

        while len(exit_statements_per_run):
            for block_address, exits in exit_statements_per_run.iteritems():
                for stmt_idx, exit_target in exits:
                    if exit_target not in self.chosen_exits:
                        # Oh we found one!
                        # The default exit should be taken no matter where it leads to
                        # Add it to the new set
                        tpl = ('default', None)
                        if tpl not in new_exit_statements_per_run[exit_target]:
                            new_exit_statements_per_run[exit_target].append(tpl)

            # Add the new ones to our global dict
            for block_address, exits in new_exit_statements_per_run.iteritems():
                for ex in exits:
                    if ex not in self.chosen_exits[block_address]:
                        self.chosen_exits[block_address].append(ex)

            # Switch them so we can process the new set
            exit_statements_per_run = new_exit_statements_per_run
            new_exit_statements_per_run = defaultdict(list)

    def _pick_statement(self, block_address, stmt_idx):
        """
        Include a statement in the final slice.

        :param block_address:   Address of the basic block.
        :param stmt_idx:        Statement ID.
        """

        # TODO: Support context-sensitivity

        self.chosen_statements[block_address].add(stmt_idx)

    def _pick_exit(self, block_address, stmt_idx, target_ips):
        """
        Include an exit in the final slice.

        :param block_address:   Address of the basic block.
        :param stmt_idx:        ID of the exit statement.
        :param target_ips:      The target address of this exit statement.
        """

        # TODO: Support context-sensitivity

        tpl = (stmt_idx, target_ips)
        if tpl not in self.chosen_exits[block_address]:
            self.chosen_exits[block_address].append(tpl)

    #
    # Helper functions
    #

    def _conditional_exits(self, block_addr):
        """
        Return a list of conditional statement exits with respect to a basic block.

        :param block_addr:  The address of the basic block.
        :return:            A list of statement IDs.
        """

        vex_block = self.project.factory.block(block_addr).vex
        lst = [ ]

        for i, stmt in enumerate(vex_block.statements):
            if isinstance(stmt, pyvex.IRStmt.Exit):
                lst.append(i)

        return lst

    def _normalize_stmt_idx(self, block_addr, stmt_idx):
        """
        For each statement ID, convert 'default' to (last_stmt_idx+1)

        :param block_addr:  The block address.
        :param stmt_idx:    Statement ID.
        :returns:           New statement ID.
        """

        if type(stmt_idx) in (int, long):
            return stmt_idx

        if stmt_idx == 'default':
            vex_block = self.project.factory.block(block_addr).vex
            return len(vex_block.statements)

        raise AngrBackwardSlicingError('Unsupported statement ID "%s"' % stmt_idx)

    @staticmethod
    def _last_branching_statement(statements):
        """
        Search for the last branching exit, just like
        #   if (t12) { PUT(184) = 0xBADF00D:I64; exit-Boring }
        and then taint the temp variable inside if predicate
        """
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

register_analysis(BackwardSlice, 'BackwardSlice')
