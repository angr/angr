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

l = logging.getLogger(name="angr.analyses.backward_slicing")

class BackwardSlice(Analysis):

    def __init__(self, cfg, cdg, ddg, cfg_node, stmt_id,
                 control_flow_slice=False,
                 no_construct=False):
        """
        Create a backward slice from a specific statement based on provided control flow graph (CFG), control
        dependence graph (CDG), and data dependence graph (DDG).

        The data dependence graph can be either CFG-based, or Value-set analysis based. A CFG-based DDG is much faster
        to generate, but it only reflects those states while generating the CFG, and it is neither sound nor accurate.
        The VSA based DDG (called VSA_DDG) is based on static analysis, which gives you a much better result.

        :param cfg: The control flow graph.
        :param cdg: The control dependence graph.
        :param ddg: The data dependence graph.
        :param irsb: The target CFGNode to reach. It should exist in the CFG.
        :param stmt_id: The target statement to reach.
        :param control_flow_slice: True/False, indicates whether we should slice only based on CFG. Sometimes when
                acquiring DDG is difficult or impossible, you can just create a slice on your CFG.
                Well, if you don't even have a CFG, then...
        :param no_construct: Only used for testing and debugging to easily create a BackwardSlice object
        """

        self._cfg = cfg
        self._cdg = cdg
        self._ddg = ddg

        self._target_cfgnode = cfg_node
        self._target_stmt_idx = stmt_id

        # Save a list of taints to beginwwith at the beginning of each SimRun
        self.initial_taints_per_run = None
        self.runs_in_slice = None
        # Log allowed statement IDs for each SimRun
        self._statements_per_run = defaultdict(set)
        # Log allowed exit statement IDs and their corresponding targets
        self._exit_statements_per_run = defaultdict(list)

        if not no_construct:
            self._construct(self._target_cfgnode, stmt_id, control_flow_slice=control_flow_slice)

    #
    # Public methods
    #

    def annotated_cfg(self, start_point=None):
        """
        Returns an AnnotatedCFG based on slicing result.
        """

        # TODO: Support context-sensitivity

        target_irsb_addr = self._target_cfgnode.addr
        target_stmt = self._target_stmt_idx
        start_point = start_point if start_point is not None else self.project.entry

        l.debug("Initializing AnnoCFG...")
        target_irsb = self._cfg.get_any_node(target_irsb_addr)
        anno_cfg = AnnotatedCFG(self.project, self._cfg, target_irsb_addr)
        if target_stmt is not -1:
            anno_cfg.set_last_stmt(target_irsb, target_stmt)

        for n in self._cfg.graph.nodes():

            run = n

            if run.addr in self._statements_per_run:
                if self._statements_per_run[run.addr] is True:
                    anno_cfg.add_simrun_to_whitelist(run.addr)
                else:
                    anno_cfg.add_statements_to_whitelist(run.addr, self._statements_per_run[run.addr])

        for src, dst in self._cfg.graph.edges():
            run = src

            if dst.addr in self._statements_per_run and src.addr in self._statements_per_run:
                anno_cfg.add_exit_to_whitelist(run.addr, dst.addr)

            # TODO: expose here, maybe?
            #anno_cfg.set_path_merge_points(self._path_merge_points)

        return anno_cfg

    def is_taint_related_to_ip(self, simrun_addr, stmt_idx, taint_type, simrun_whitelist=None):
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
            elif descendant.type == 'reg' and descendant.reg == self.project.arch.ip_offset:
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
                        descendant.reg in (self.project.arch.sp_offset, self.project.arch.bp_offset)
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

        # TODO: Support context-sensitivity!

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

        self._statements_per_run = { }
        while stack:
            # Pop one out
            block = stack.pop()
            if block.addr not in self._statements_per_run:
                self._statements_per_run[block.addr] = True
                # Get all successors of that block
                successors = reversed_cfg.successors(block)
                for succ in successors:
                    stack.append(succ)
                    self.runs_in_slice.add_edge(succ.addr, block.addr)

    def _construct_default(self, cfg_node, stmt_id):
        """
        Create a backward slice from a specific statement in a specific sim_run. This is done by traverse the CFG
        backwards, and mark all tainted statements based on dependence graphs (CDG and DDG) provided initially. The
        traversal terminated when we reach the entry point, or when there is no unresolved dependencies.

        :param cfg_node: The CFGNode instance where the backward slice starts. It must be included in CFG and CDG.
        :param stmt_id: ID of the target statement where the backward slice starts.
        :return: None
        """

        # TODO: Support context-sensitivity

        self.taint_graph = networkx.DiGraph()

        if cfg_node not in self._cfg.graph:
            raise AngrBackwardSlicingError('Target CFGNode %s is not in the CFG.', cfg_node)

        taints = set()
        accessed_taints = set()

        if stmt_id == -1:
            new_taints = self._handle_control_dependence(cfg_node)
            taints |= new_taints

        else:
            cl = CodeLocation(cfg_node, stmt_id)
            taints.add(cl)

        while taints:
            # Pop a tainted code location
            tainted_cl = taints.pop()

            # Mark it as picked
            self._pick_statement(tainted_cl.simrun_addr, tainted_cl.stmt_idx)

            # Mark it as accessed
            accessed_taints.add(tainted_cl)

            # Pick all its data dependencies from data dependency graph
            if tainted_cl in self._ddg:
                predecessors = self._ddg.get_predecessors(tainted_cl)

                for p in predecessors:
                    if p not in accessed_taints:
                        taints.add(p)

            # Handle the control dependence
            for n in self._cfg.get_all_nodes(tainted_cl.simrun_addr):
                new_taints = self._handle_control_dependence(n)

                for taint in new_taints:
                    if taint not in accessed_taints:
                        taints.add(taint)

        # In the end, map the taint graph onto CFG
        self._map_to_cfg()

    def _find_exits(self, src_block, target_block):
        """
        Source block has more than one exit, and through some of those exits, the control flow can eventually go to
        the target block. This method returns exits that lead to the target block.

        :param src_block: The block that has multiple exits
        :param target_block: The target block to reach
        :return: a dict of statement ID -> a list of target IPs (or None if the exit should not be taken), each
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

        # TODO: Support hooks

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
        all_simple_paths = networkx.all_simple_paths(self._cfg.graph, src_block, target_block)
        for simple_path in all_simple_paths:
            if len(simple_path) <= 1:
                # Oops, it looks that src_block and target_block are the same guy?
                continue

            # Get the first two nodes
            a, b = simple_path[0], simple_path[1]
            # Get the exit statement ID from CFG
            exit_stmt_id = self._cfg.get_exit_stmt_idx(a, b)
            # Mark it!
            if exit_stmt_ids[exit_stmt_id] is None:
                exit_stmt_ids[exit_stmt_id] = [ b.addr ]
            else:
                exit_stmt_ids[exit_stmt_id].append(b.addr)

        return exit_stmt_ids

    def _handle_control_dependence(self, target_node):
        """
        Based on control dependence graph, pick all exits (statements) that lead to the target.

        :param target_node: A CFGNode instance
        :return: A set of new tainted code locations
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

        return new_taints

    def _map_to_cfg(self):
        """
        Map our current slice to CFG.

        Based on self._statements_per_run and self._exit_statements_per_run, this method will traverse the CFG and
        check if there is any missing block on the path. If there is, the default exit of that missing block will be
        included in the slice. This is because Slicecutor cannot skip individual basic blocks along a path.
        """

        exit_statements_per_run = self._exit_statements_per_run
        new_exit_statements_per_run = defaultdict(list)

        while len(exit_statements_per_run):
            for block_address, exits in exit_statements_per_run.iteritems():
                for stmt_idx, exit_target in exits:
                    if exit_target not in self._exit_statements_per_run:
                        # Oh we found one!
                        # The default exit should be taken no matter where it leads to
                        # Add it to the new set
                        tpl = ('default', None)
                        if tpl not in new_exit_statements_per_run[exit_target]:
                            new_exit_statements_per_run[exit_target].append(tpl)

            # Add the new ones to our global dict
            for block_address, exits in new_exit_statements_per_run.iteritems():
                for ex in exits:
                    if ex not in self._exit_statements_per_run[block_address]:
                        self._exit_statements_per_run[block_address].append(ex)

            # Switch them so we can process the new set
            exit_statements_per_run = new_exit_statements_per_run
            new_exit_statements_per_run = defaultdict(list)

    def _pick_statement(self, block_address, stmt_idx):
        """
        Include a statement in the final slice.

        :param block_address: Address of the basic block
        :param stmt_idx: Statement ID
        """

        # TODO: Support context-sensitivity

        self._statements_per_run[block_address].add(stmt_idx)

    def _pick_exit(self, block_address, stmt_idx, target_ips):
        """
        Include an exit in the final slice

        :param block_address: Address of the basic block
        :param stmt_idx: ID of the exit statement
        :param target_ips: The target address of this exit statement
        """

        # TODO: Support context-sensitivity

        tpl = (stmt_idx, target_ips)
        if tpl not in self._exit_statements_per_run[block_address]:
            self._exit_statements_per_run[block_address].append(tpl)

    #
    # Helper functions
    #

    def _normalize_stmt_idx(self, block_addr, stmt_idx):
        """
        For each statement ID, convert 'default' to (last_stmt_idx+1)

        :param block_addr: The block address
        :param stmt_idx: Statement ID
        :return: New statement ID
        """

        if type(stmt_idx) in (int, long):
            return stmt_idx

        if stmt_idx == 'default':
            vex_block = self.project.factory.block(block_addr).vex
            return len(vex_block.statements)

        raise AngrBackwardSlicingError('Unsupported statement ID "%s"' % stmt_idx)

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

register_analysis(BackwardSlice, 'BackwardSlice')
