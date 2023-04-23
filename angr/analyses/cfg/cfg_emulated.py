import itertools
import logging
import sys
from collections import defaultdict
from functools import reduce
from typing import Dict, List

import angr
import claripy
import networkx
import pyvex
from archinfo import ArchARM

from angr.analyses import ForwardAnalysis
from angr.utils.graph import GraphUtils
from angr.analyses import AnalysesHub
from ... import BP, BP_BEFORE, BP_AFTER, SIM_PROCEDURES, procedures
from ... import options as o
from ...codenode import BlockNode
from ...engines.procedure import ProcedureEngine
from ...exploration_techniques.loop_seer import LoopSeer
from ...exploration_techniques.slicecutor import Slicecutor
from ...exploration_techniques.explorer import Explorer
from ...exploration_techniques.lengthlimiter import LengthLimiter
from ...errors import (
    AngrCFGError,
    AngrError,
    AngrSkipJobNotice,
    SimError,
    SimValueError,
    SimSolverModeError,
    SimFastPathError,
    SimIRSBError,
    AngrExitError,
    SimEmptyCallStackError,
)
from ...sim_state import SimState
from ...state_plugins.callstack import CallStack
from ...state_plugins.sim_action import SimActionData
from ...knowledge_plugins.cfg import CFGENode, IndirectJump
from ...utils.constants import DEFAULT_STATEMENT
from ..cdg import CDG
from ..ddg import DDG
from ..backward_slice import BackwardSlice
from ..loopfinder import LoopFinder, Loop
from .cfg_base import CFGBase
from .cfg_job_base import BlockID, CFGJobBase

l = logging.getLogger(name=__name__)


class CFGJob(CFGJobBase):
    """
    The job class that CFGEmulated uses.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        #
        # local variables used during analysis
        #

        if self.jumpkind is None:
            # load jumpkind from path.state.scratch
            self.jumpkind = "Ijk_Boring" if self.state.history.jumpkind is None else self.state.history.jumpkind

        self.call_stack_suffix = None
        self.current_function = None

        self.cfg_node = None
        self.sim_successors = None
        self.exception_info = None
        self.successor_status = None

        self.extra_info = None

    @property
    def block_id(self):
        if self._block_id is None:
            # generate a new block ID
            self._block_id = CFGEmulated._generate_block_id(
                self.call_stack.stack_suffix(self._context_sensitivity_level), self.addr, self.is_syscall
            )
        return self._block_id

    @property
    def is_syscall(self):
        return self.jumpkind is not None and self.jumpkind.startswith("Ijk_Sys")

    def __hash__(self):
        return hash(self.block_id)


class PendingJob:
    """
    A PendingJob is whatever will be put into our pending_exit list. A pending exit is an entry that created by the
    returning of a call or syscall. It is "pending" since we cannot immediately figure out whether this entry will
    be executed or not. If the corresponding call/syscall intentially doesn't return, then the pending exit will be
    removed. If the corresponding call/syscall returns, then the pending exit will be removed as well (since a real
    entry is created from the returning and will be analyzed later). If the corresponding call/syscall might
    return, but for some reason (for example, an unsupported instruction is met during the analysis) our analysis
    does not return properly, then the pending exit will be picked up and put into remaining_jobs list.
    """

    def __init__(
        self, caller_func_addr, returning_source, state, src_block_id, src_exit_stmt_idx, src_exit_ins_addr, call_stack
    ):
        """
        :param returning_source:    Address of the callee function. It might be None if address of the callee is not
                                    resolvable.
        :param state:               The state after returning from the callee function. Of course there is no way to get
                                    a precise state without emulating the execution of the callee, but at least we can
                                    properly adjust the stack and registers to imitate the real returned state.
        :param call_stack:          A callstack.
        """

        self.caller_func_addr = caller_func_addr
        self.returning_source = returning_source
        self.state = state
        self.src_block_id = src_block_id
        self.src_exit_stmt_idx = src_exit_stmt_idx
        self.src_exit_ins_addr = src_exit_ins_addr
        self.call_stack = call_stack

    def __repr__(self):
        return "<PendingJob to {}, from function {}>".format(
            self.state.ip, hex(self.returning_source) if self.returning_source is not None else "Unknown"
        )

    def __hash__(self):
        return hash(
            (
                self.caller_func_addr,
                self.returning_source,
                self.src_block_id,
                self.src_exit_stmt_idx,
                self.src_exit_ins_addr,
            )
        )

    def __eq__(self, other):
        if not isinstance(other, PendingJob):
            return False
        return (
            self.caller_func_addr == other.caller_func_addr
            and self.returning_source == other.returning_source
            and self.src_block_id == other.src_block_id
            and self.src_exit_stmt_idx == other.src_exit_stmt_idx
            and self.src_exit_ins_addr == other.src_exit_ins_addr
        )


class CFGEmulated(ForwardAnalysis, CFGBase):  # pylint: disable=abstract-method
    """
    This class represents a control-flow graph.
    """

    tag = "CFGEmulated"

    def __init__(
        self,
        context_sensitivity_level=1,
        start=None,
        avoid_runs=None,
        enable_function_hints=False,
        call_depth=None,
        call_tracing_filter=None,
        initial_state=None,
        starts=None,
        keep_state=False,
        indirect_jump_target_limit=100000,
        resolve_indirect_jumps=True,
        enable_advanced_backward_slicing=False,
        enable_symbolic_back_traversal=False,
        indirect_jump_resolvers=None,
        additional_edges=None,
        no_construct=False,
        normalize=False,
        max_iterations=1,
        address_whitelist=None,
        base_graph=None,
        iropt_level=None,
        max_steps=None,
        state_add_options=None,
        state_remove_options=None,
        model=None,
    ):
        """
        All parameters are optional.

        :param context_sensitivity_level:           The level of context-sensitivity of this CFG (see documentation for
                                                    further details). It ranges from 0 to infinity. Default 1.
        :param avoid_runs:                          A list of runs to avoid.
        :param enable_function_hints:               Whether to use function hints (constants that might be used as exit
                                                    targets) or not.
        :param call_depth:                          How deep in the call stack to trace.
        :param call_tracing_filter:                 Filter to apply on a given path and jumpkind to determine if it
                                                    should be skipped when call_depth is reached.
        :param initial_state:                       An initial state to use to begin analysis.
        :param iterable starts:                     A collection of starting points to begin analysis. It can contain
                                                    the following three different types of entries: an address specified
                                                    as an integer, a 2-tuple that includes an integer address and a
                                                    jumpkind, or a SimState instance. Unsupported entries in starts will
                                                    lead to an AngrCFGError being raised.
        :param keep_state:                          Whether to keep the SimStates for each CFGNode.
        :param resolve_indirect_jumps:              Whether to enable the indirect jump resolvers for resolving indirect
                                                    jumps
        :param enable_advanced_backward_slicing:    Whether to enable an intensive technique for resolving indirect
                                                    jumps
        :param enable_symbolic_back_traversal:      Whether to enable an intensive technique for resolving indirect
                                                    jumps
        :param list indirect_jump_resolvers:        A custom list of indirect jump resolvers. If this list is None or
                                                    empty,
                                                    default indirect jump resolvers specific to this architecture and
                                                    binary types will be loaded.
        :param additional_edges:                    A dict mapping addresses of basic blocks to addresses of
                                                    successors to manually include and analyze forward from.
        :param bool no_construct:                   Skip the construction procedure. Only used in unit-testing.
        :param bool normalize:                      If the CFG as well as all Function graphs should be normalized or
                                                    not.
        :param int max_iterations:                  The maximum number of iterations that each basic block should be
                                                    "executed". 1 by default. Larger numbers of iterations are usually
                                                    required for complex analyses like loop analysis.
        :param iterable address_whitelist:          A list of allowed addresses. Any basic blocks outside of this
                                                    collection of addresses will be ignored.
        :param networkx.DiGraph base_graph:         A basic control flow graph to follow. Each node inside this graph
                                                    must have the following properties: `addr` and `size`. CFG recovery
                                                    will strictly follow nodes and edges shown in the graph, and discard
                                                    any contorl flow that does not follow an existing edge in the base
                                                    graph. For example, you can pass in a Function local transition
                                                    graph as the base graph, and CFGEmulated will traverse nodes and
                                                    edges and extract useful information.
        :param int iropt_level:                     The optimization level of VEX IR (0, 1, 2). The default level will
                                                    be used if `iropt_level` is None.
        :param int max_steps:                       The maximum number of basic blocks to recover forthe longest path
                                                    from each start before pausing the recovery procedure.
        :param state_add_options:                   State options that will be added to the initial state.
        :param state_remove_options:                State options that will be removed from the initial state.
        """
        ForwardAnalysis.__init__(self, order_jobs=base_graph is not None)
        CFGBase.__init__(
            self,
            "emulated",
            context_sensitivity_level,
            normalize=normalize,
            resolve_indirect_jumps=resolve_indirect_jumps,
            indirect_jump_resolvers=indirect_jump_resolvers,
            indirect_jump_target_limit=indirect_jump_target_limit,
            model=model,
        )

        if start is not None:
            l.warning("`start` is deprecated. Please consider using `starts` instead in your code.")
            self._starts = (start,)
        else:
            if isinstance(starts, (list, set)):
                self._starts = tuple(starts)
            elif isinstance(starts, tuple) or starts is None:
                self._starts = starts
            else:
                raise AngrCFGError("Unsupported type of the `starts` argument.")

        if enable_advanced_backward_slicing or enable_symbolic_back_traversal:
            l.warning("`advanced backward slicing` and `symbolic back traversal` are deprecated.")
            l.warning(
                "Please use `resolve_indirect_jumps` to resolve indirect jumps using different resolvers instead."
            )

        self._iropt_level = iropt_level
        self._avoid_runs = avoid_runs
        self._enable_function_hints = enable_function_hints
        self._call_depth = call_depth
        self._call_tracing_filter = call_tracing_filter
        self._initial_state = initial_state
        self._keep_state = keep_state
        self._advanced_backward_slicing = enable_advanced_backward_slicing
        self._enable_symbolic_back_traversal = enable_symbolic_back_traversal
        self._additional_edges = additional_edges if additional_edges else {}
        self._max_steps = max_steps
        self._state_add_options = state_add_options if state_add_options is not None else set()
        self._state_remove_options = state_remove_options if state_remove_options is not None else set()
        self._state_add_options.update([o.SYMBOL_FILL_UNCONSTRAINED_MEMORY, o.SYMBOL_FILL_UNCONSTRAINED_REGISTERS])

        # add the track_memory_option if the enable function hint flag is set
        if self._enable_function_hints and o.TRACK_MEMORY_ACTIONS not in self._state_add_options:
            self._state_add_options.add(o.TRACK_MEMORY_ACTIONS)

        # more initialization

        self._symbolic_function_initial_state = {}
        self._function_input_states = None
        self._unresolvable_runs = set()

        # Stores the index for each CFGNode in this CFG after a quasi-topological sort (currently a DFS)
        # TODO: remove it since it's no longer used
        self._quasi_topological_order = {}
        # A copy of all entry points in this CFG. Integers
        self._entry_points = []

        self._max_iterations = max_iterations
        self._address_whitelist = set(address_whitelist) if address_whitelist is not None else None
        self._base_graph = base_graph
        self._node_addr_visiting_order = []

        if self._base_graph:
            sorted_nodes = GraphUtils.quasi_topological_sort_nodes(self._base_graph)
            self._node_addr_visiting_order = [n.addr for n in sorted_nodes]

        self._sanitize_parameters()

        self._executable_address_ranges = []
        self._executable_address_ranges = self._executable_memory_regions()

        # These save input states of functions. It will be discarded after the CFG is constructed
        self._function_input_states = {}
        self._loop_back_edges = []
        self._overlapped_loop_headers = []
        self._pending_function_hints = set()
        # A dict to log edges and the jumpkind between each basic block
        self._edge_map = defaultdict(list)

        self._model._iropt_level = self._iropt_level

        self._start_keys = []  # a list of block IDs of all starts

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_Ret that is a simulated exit
        # for the retn address. There are certain cases that the control flow
        # never returns to the next instruction of a callsite due to
        # imprecision of the concrete execution. So we save those simulated
        # exits here to increase our code coverage. Of course the real retn from
        # that call always precedes those "fake" retns.
        self._pending_jobs = defaultdict(list)  # Dict[BlockID, List[PendingJob]]

        # Counting how many times a basic block is traced into
        self._traced_addrs = defaultdict(lambda: defaultdict(int))

        # A dict that collects essential parameters to properly reconstruct initial state for a block
        self._block_artifacts = {}
        self._analyzed_addrs = set()
        self._non_returning_functions = set()

        self._pending_edges = defaultdict(list)

        if not no_construct:
            self._initialize_cfg()
            self._analyze()

    #
    # Public methods
    #

    def copy(self) -> "CFGEmulated":
        """
        Make a copy of the CFG.

        :return: A copy of the CFG instance.
        """
        new_cfg = CFGEmulated.__new__(CFGEmulated)
        super().make_copy(new_cfg)

        new_cfg._indirect_jump_target_limit = self._indirect_jump_target_limit
        new_cfg.named_errors = defaultdict(list, self.named_errors)
        new_cfg.errors = list(self.errors)
        new_cfg._fail_fast = self._fail_fast
        new_cfg._max_steps = self._max_steps
        new_cfg.project = self.project

        # Intelligently (or stupidly... you tell me) fill it up
        new_cfg._edge_map = self._edge_map.copy()
        new_cfg._loop_back_edges = self._loop_back_edges[::]
        new_cfg._executable_address_ranges = self._executable_address_ranges[::]
        new_cfg._unresolvable_runs = self._unresolvable_runs.copy()
        new_cfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_cfg._thumb_addrs = self._thumb_addrs.copy()
        new_cfg._keep_state = self._keep_state

        return new_cfg

    def resume(self, starts=None, max_steps=None):
        """
        Resume a paused or terminated control flow graph recovery.

        :param iterable starts: A collection of new starts to resume from. If `starts` is None, we will resume CFG
                                recovery from where it was paused before.
        :param int max_steps:   The maximum number of blocks on the longest path starting from each start before pausing
                                the recovery.
        :return: None
        """

        self._should_abort = False

        self._starts = starts
        self._max_steps = max_steps

        if self._starts is None:
            self._starts = []

        if self._starts:
            self._sanitize_starts()

        self._analyze()

    def remove_cycles(self):
        """
        Forces graph to become acyclic, removes all loop back edges and edges between overlapped loop headers and their
        successors.
        """
        # loop detection
        # only detect loops after potential graph normalization
        if not self._loop_back_edges:
            l.debug("Detecting loops...")
            self._detect_loops()

        l.debug("Removing cycles...")
        l.debug("There are %d loop back edges.", len(self._loop_back_edges))
        l.debug("And there are %d overlapping loop headers.", len(self._overlapped_loop_headers))
        # First break all detected loops
        for b1, b2 in self._loop_back_edges:
            if self._graph.has_edge(b1, b2):
                l.debug("Removing loop back edge %s -> %s", b1, b2)
                self._graph.remove_edge(b1, b2)
        # Then remove all outedges from overlapped loop headers
        for b in self._overlapped_loop_headers:
            successors = self._graph.successors(b)
            for succ in successors:
                self._graph.remove_edge(b, succ)
                l.debug("Removing partial loop header edge %s -> %s", b, succ)

    def downsize(self):
        """
        Remove saved states from all CFGNodes to reduce memory usage.

        :return: None
        """

        for cfg_node in self._nodes.values():
            cfg_node.downsize()

    def unroll_loops(self, max_loop_unrolling_times):
        """
        Unroll loops for each function. The resulting CFG may still contain loops due to recursion, function calls, etc.

        :param int max_loop_unrolling_times: The maximum iterations of unrolling.
        :return: None
        """

        if not isinstance(max_loop_unrolling_times, int) or max_loop_unrolling_times < 0:
            raise AngrCFGError(
                "Max loop unrolling times must be set to an integer greater than or equal to 0 if "
                + "loop unrolling is enabled."
            )

        def _unroll(graph: networkx.DiGraph, loop: Loop):
            """
            The loop callback method where loops are unrolled.

            :param graph: The control flow graph.
            :param loop: The loop instance.
            :return: None
            """

            for back_edge in loop.continue_edges:
                loop_body_addrs = {n.addr for n in loop.body_nodes}
                src_blocknode: BlockNode = back_edge[0]
                dst_blocknode: BlockNode = back_edge[1]

                for src in self.get_all_nodes(src_blocknode.addr):
                    for dst in graph.successors(src):
                        if dst.addr != dst_blocknode.addr:
                            continue

                        # Duplicate the dst node
                        new_dst = dst.copy()
                        new_dst.looping_times = dst.looping_times + 1
                        if (
                            new_dst not in graph
                            and
                            # If the new_dst is already in the graph, we don't want to keep unrolling
                            # the this loop anymore since it may *create* a new loop. Of course we
                            # will lose some edges in this way, but in general it is acceptable.
                            new_dst.looping_times <= max_loop_unrolling_times
                        ):
                            # Log all successors of the dst node
                            dst_successors = graph.successors(dst)
                            # Add new_dst to the graph
                            edge_data = graph.get_edge_data(src, dst)
                            graph.add_edge(src, new_dst, **edge_data)
                            for ds in dst_successors:
                                if ds.looping_times == 0 and ds.addr not in loop_body_addrs:
                                    edge_data = graph.get_edge_data(dst, ds)
                                    graph.add_edge(new_dst, ds, **edge_data)

                        graph.remove_edge(src, dst)

        self._detect_loops(loop_callback=_unroll)

    def force_unroll_loops(self, max_loop_unrolling_times):
        """
        Unroll loops globally. The resulting CFG does not contain any loop, but this method is slow on large graphs.

        :param int max_loop_unrolling_times: The maximum iterations of unrolling.
        :return: None
        """

        if not isinstance(max_loop_unrolling_times, int) or max_loop_unrolling_times < 0:
            raise AngrCFGError(
                "Max loop unrolling times must be set to an integer greater than or equal to 0 if "
                + "loop unrolling is enabled."
            )

        # Traverse the CFG and try to find the beginning of loops
        loop_backedges = []

        start = self._starts[0]
        if isinstance(start, tuple):
            start, _ = start  # pylint: disable=unpacking-non-sequence
        start_node = self.get_any_node(start)
        if start_node is None:
            raise AngrCFGError("Cannot find start node when trying to unroll loops. The CFG might be empty.")

        graph_copy = networkx.DiGraph(self.graph)

        while True:
            cycles_iter = networkx.simple_cycles(graph_copy)
            try:
                cycle = next(cycles_iter)
            except StopIteration:
                break

            loop_backedge = (None, None)

            for n in networkx.dfs_preorder_nodes(graph_copy, source=start_node):
                if n in cycle:
                    idx = cycle.index(n)
                    if idx == 0:
                        loop_backedge = (cycle[-1], cycle[idx])
                    else:
                        loop_backedge = (cycle[idx - 1], cycle[idx])
                    break

            if loop_backedge not in loop_backedges:
                loop_backedges.append(loop_backedge)

            # Create a common end node for all nodes whose out_degree is 0
            end_nodes = [n for n in graph_copy.nodes() if graph_copy.out_degree(n) == 0]
            new_end_node = "end_node"

            if not end_nodes:
                # We gotta randomly break a loop
                cycles = sorted(networkx.simple_cycles(graph_copy), key=len)
                first_cycle = cycles[0]
                if len(first_cycle) == 1:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[0])
                else:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[1])
                end_nodes = [n for n in graph_copy.nodes() if graph_copy.out_degree(n) == 0]

            for en in end_nodes:
                graph_copy.add_edge(en, new_end_node)

            # postdoms = self.immediate_postdominators(new_end_node, target_graph=graph_copy)
            # reverse_postdoms = defaultdict(list)
            # for k, v in postdoms.items():
            #    reverse_postdoms[v].append(k)

            # Find all loop bodies
            # for src, dst in loop_backedges:
            #    nodes_in_loop = { src, dst }

            #    while True:
            #        new_nodes = set()

            #        for n in nodes_in_loop:
            #            if n in reverse_postdoms:
            #                for node in reverse_postdoms[n]:
            #                    if node not in nodes_in_loop:
            #                        new_nodes.add(node)

            #        if not new_nodes:
            #            break

            #        nodes_in_loop |= new_nodes

            # Unroll the loop body
            # TODO: Finish the implementation

            graph_copy.remove_node(new_end_node)
            src, dst = loop_backedge
            if graph_copy.has_edge(src, dst):  # It might have been removed before
                # Duplicate the dst node
                new_dst = dst.copy()
                new_dst.looping_times = dst.looping_times + 1
                if (
                    new_dst not in graph_copy
                    and
                    # If the new_dst is already in the graph, we don't want to keep unrolling
                    # the this loop anymore since it may *create* a new loop. Of course we
                    # will lose some edges in this way, but in general it is acceptable.
                    new_dst.looping_times <= max_loop_unrolling_times
                ):
                    # Log all successors of the dst node
                    dst_successors = list(graph_copy.successors(dst))
                    # Add new_dst to the graph
                    edge_data = graph_copy.get_edge_data(src, dst)
                    graph_copy.add_edge(src, new_dst, **edge_data)
                    for ds in dst_successors:
                        if ds.looping_times == 0 and ds not in cycle:
                            edge_data = graph_copy.get_edge_data(dst, ds)
                            graph_copy.add_edge(new_dst, ds, **edge_data)
                # Remove the original edge
                graph_copy.remove_edge(src, dst)

        # Update loop backedges
        self._loop_back_edges = loop_backedges

        self.model.graph = graph_copy

    def immediate_dominators(self, start, target_graph=None):
        """
        Get all immediate dominators of sub graph from given node upwards.

        :param str start: id of the node to navigate forwards from.
        :param networkx.classes.digraph.DiGraph target_graph: graph to analyse, default is self.graph.

        :return: each node of graph as index values, with element as respective node's immediate dominator.
        :rtype: dict
        """
        return self._immediate_dominators(start, target_graph=target_graph, reverse_graph=False)

    def immediate_postdominators(self, end, target_graph=None):
        """
        Get all immediate postdominators of sub graph from given node upwards.

        :param str start: id of the node to navigate forwards from.
        :param networkx.classes.digraph.DiGraph target_graph: graph to analyse, default is self.graph.

        :return: each node of graph as index values, with element as respective node's immediate dominator.
        :rtype: dict
        """
        return self._immediate_dominators(end, target_graph=target_graph, reverse_graph=True)

    def remove_fakerets(self):
        """
        Get rid of fake returns (i.e., Ijk_FakeRet edges) from this CFG

        :return: None
        """
        fakeret_edges = [
            (src, dst) for src, dst, data in self.graph.edges(data=True) if data["jumpkind"] == "Ijk_FakeRet"
        ]
        self.graph.remove_edges_from(fakeret_edges)

    def get_topological_order(self, cfg_node):
        """
        Get the topological order of a CFG Node.

        :param cfg_node: A CFGNode instance.
        :return: An integer representing its order, or None if the CFGNode does not exist in the graph.
        """

        if not self._quasi_topological_order:
            self._quasi_topological_sort()

        return self._quasi_topological_order.get(cfg_node, None)

    def get_subgraph(self, starting_node, block_addresses):
        """
        Get a sub-graph out of a bunch of basic block addresses.

        :param CFGNode starting_node: The beginning of the subgraph
        :param iterable block_addresses: A collection of block addresses that should be included in the subgraph if
                                        there is a path between `starting_node` and a CFGNode with the specified
                                        address, and all nodes on the path should also be included in the subgraph.
        :return: A new CFG that only contain the specific subgraph.
        :rtype: CFGEmulated
        """

        graph = networkx.DiGraph()

        if starting_node not in self.graph:
            raise AngrCFGError(
                'get_subgraph(): the specified "starting_node" %s does not exist in the current CFG.' % starting_node
            )

        addr_set = set(block_addresses)

        graph.add_node(starting_node)
        queue = [starting_node]

        while queue:
            node = queue.pop()
            for _, dst, data in self.graph.out_edges([node], data=True):
                if dst not in graph and dst.addr in addr_set:
                    graph.add_edge(node, dst, **data)
                    queue.append(dst)

        cfg = self.copy()
        cfg._graph = graph
        cfg._starts = (starting_node.addr,)

        return cfg

    def get_function_subgraph(self, start, max_call_depth=None):
        """
        Get a sub-graph of a certain function.

        :param start: The function start. Currently it should be an integer.
        :param max_call_depth: Call depth limit. None indicates no limit.
        :return: A CFG instance which is a sub-graph of self.graph
        """

        # FIXME: syscalls are not supported
        # FIXME: start should also take a CFGNode instance

        start_node = self.get_any_node(start)

        node_wrapper = (start_node, 0)
        stack = [node_wrapper]
        traversed_nodes = {start_node}
        subgraph_nodes = {start_node}

        while stack:
            nw = stack.pop()
            n, call_depth = nw[0], nw[1]

            # Get successors
            edges = self.graph.out_edges(n, data=True)

            for _, dst, data in edges:
                if dst not in traversed_nodes:
                    # We see a new node!
                    traversed_nodes.add(dst)

                    if data["jumpkind"] == "Ijk_Call":
                        if max_call_depth is None or (max_call_depth is not None and call_depth < max_call_depth):
                            subgraph_nodes.add(dst)
                            new_nw = (dst, call_depth + 1)
                            stack.append(new_nw)
                    elif data["jumpkind"] == "Ijk_Ret":
                        if call_depth > 0:
                            subgraph_nodes.add(dst)
                            new_nw = (dst, call_depth - 1)
                            stack.append(new_nw)
                    else:
                        subgraph_nodes.add(dst)
                        new_nw = (dst, call_depth)
                        stack.append(new_nw)

        # subgraph = networkx.subgraph(self.graph, subgraph_nodes)
        subgraph = self.graph.subgraph(subgraph_nodes).copy()

        # Make it a CFG instance
        subcfg = self.copy()
        subcfg._graph = subgraph
        subcfg._starts = (start,)

        return subcfg

    @property
    def context_sensitivity_level(self):
        return self._context_sensitivity_level

    #
    # Serialization
    #

    def __setstate__(self, s):
        self.project: angr.Project = s["project"]
        self.indirect_jumps: Dict[int, IndirectJump] = s["indirect_jumps"]
        self._loop_back_edges = s["_loop_back_edges"]
        self._thumb_addrs = s["_thumb_addrs"]
        self._unresolvable_runs = s["_unresolvable_runs"]
        self._executable_address_ranges = s["_executable_address_ranges"]
        self._iropt_level = s["_iropt_level"]
        self._model = s["_model"]

    def __getstate__(self):
        s = {
            "project": self.project,
            "indirect_jumps": self.indirect_jumps,
            "_loop_back_edges": self._loop_back_edges,
            "_nodes_by_addr": self._nodes_by_addr,
            "_thumb_addrs": self._thumb_addrs,
            "_unresolvable_runs": self._unresolvable_runs,
            "_executable_address_ranges": self._executable_address_ranges,
            "_iropt_level": self._iropt_level,
            "_model": self._model,
        }

        return s

    #
    # Properties
    #

    @property
    def graph(self):
        return self._model.graph

    @property
    def unresolvables(self):
        """
        Get those SimRuns that have non-resolvable exits.

        :return:    A set of SimRuns
        :rtype:     set
        """
        return self._unresolvable_runs

    @property
    def deadends(self):
        """
        Get all CFGNodes that has an out-degree of 0

        :return: A list of CFGNode instances
        :rtype:  list
        """
        if self.graph is None:
            raise AngrCFGError("CFG hasn't been generated yet.")

        deadends = [i for i in self.graph if self.graph.out_degree(i) == 0]

        return deadends

    #
    # Private methods
    #

    # Initialization related methods

    def _sanitize_parameters(self):
        """
        Perform a sanity check on parameters passed in to CFG.__init__().
        An AngrCFGError is raised if any parameter fails the sanity check.

        :return: None
        """

        # Check additional_edges
        if isinstance(self._additional_edges, (list, set, tuple)):
            new_dict = defaultdict(list)
            for s, d in self._additional_edges:
                new_dict[s].append(d)
            self._additional_edges = new_dict

        elif isinstance(self._additional_edges, dict):
            pass

        else:
            raise AngrCFGError("Additional edges can only be a list, set, tuple, or a dict.")

        # Check _advanced_backward_slicing
        if self._advanced_backward_slicing and self._enable_symbolic_back_traversal:
            raise AngrCFGError("Advanced backward slicing and symbolic back traversal cannot both be enabled.")

        if self._advanced_backward_slicing and not self._keep_state:
            raise AngrCFGError("Keep state must be enabled if advanced backward slicing is enabled.")

        # Sanitize avoid_runs
        self._avoid_runs = [] if self._avoid_runs is None else self._avoid_runs
        if not isinstance(self._avoid_runs, (list, set)):
            raise AngrCFGError('"avoid_runs" must either be None, or a list or a set.')

        self._sanitize_starts()

    def _sanitize_starts(self):
        # Sanitize starts
        # Convert self._starts to a list of SimState instances or tuples of (ip, jumpkind)
        if self._starts is None:
            self._starts = ((self.project.entry, None),)

        else:
            new_starts = []
            for item in self._starts:
                if isinstance(item, tuple):
                    if len(item) != 2:
                        raise AngrCFGError('Unsupported item in "starts": %s' % str(item))

                    new_starts.append(item)
                elif isinstance(item, int):
                    new_starts.append((item, None))

                elif isinstance(item, SimState):
                    new_starts.append(item)

                else:
                    raise AngrCFGError('Unsupported item type in "starts": %s' % type(item))

            self._starts = new_starts

        if not self._starts:
            raise AngrCFGError("At least one start must be provided")

    # CFG construction
    # The main loop and sub-methods

    def _job_key(self, job):
        """
        Get the key for a specific CFG job. The key is a context-sensitive block ID.

        :param CFGJob job: The CFGJob instance.
        :return:             The block ID of the specific CFG job.
        :rtype:              BlockID
        """

        return job.block_id

    def _job_sorting_key(self, job):
        """
        Get the sorting key of a CFGJob instance.

        :param CFGJob job: the CFGJob object.
        :return: An integer that determines the order of this job in the queue.
        :rtype: int
        """

        if self._base_graph is None:
            # we don't do sorting if there is no base_graph
            return 0

        MAX_JOBS = 1000000

        if job.addr not in self._node_addr_visiting_order:
            return MAX_JOBS

        return self._node_addr_visiting_order.index(job.addr)

    def _pre_analysis(self):
        """
        Initialization work. Executed prior to the analysis.

        :return: None
        """

        # Fill up self._starts
        for item in self._starts:
            callstack = None
            if isinstance(item, tuple):
                # (addr, jumpkind)
                ip = item[0]
                state = self._create_initial_state(item[0], item[1])

            elif isinstance(item, SimState):
                # SimState
                state = item.copy()  # pylint: disable=no-member
                ip = state.solver.eval_one(state.ip)
                self._reset_state_mode(state, "fastpath")

            else:
                raise AngrCFGError("Unsupported CFG start type: %s." % str(type(item)))

            self._symbolic_function_initial_state[ip] = state
            path_wrapper = CFGJob(ip, state, self._context_sensitivity_level, None, None, call_stack=callstack)
            key = path_wrapper.block_id
            if key not in self._start_keys:
                self._start_keys.append(key)

            self._insert_job(path_wrapper)
            self._register_analysis_job(path_wrapper.func_addr, path_wrapper)

    def _intra_analysis(self):
        """
        During the analysis. We process function hints here.

        :return: None
        """

        if self._pending_function_hints:
            self._process_hints(self._analyzed_addrs)

    def _job_queue_empty(self):
        """
        A callback method called when the job queue is empty.

        :return: None
        """

        self._iteratively_clean_pending_exits()

        while self._pending_jobs:
            # We don't have any exits remaining. Let's pop out a pending exit
            pending_job = self._get_one_pending_job()
            if pending_job is None:
                continue

            self._insert_job(pending_job)
            self._register_analysis_job(pending_job.func_addr, pending_job)
            break

    def _create_initial_state(self, ip, jumpkind):
        """
        Obtain a SimState object for a specific address

        Fastpath means the CFG generation will work in an IDA-like way, in which it will not try to execute every
        single statement in the emulator, but will just do the decoding job. This is much faster than the old way.

        :param int ip: The instruction pointer
        :param str jumpkind: The jumpkind upon executing the block
        :return: The newly-generated state
        :rtype: SimState
        """

        jumpkind = "Ijk_Boring" if jumpkind is None else jumpkind

        if self._initial_state is None:
            state = self.project.factory.blank_state(
                addr=ip,
                mode="fastpath",
                add_options=self._state_add_options,
                remove_options=self._state_remove_options,
            )
            self._initial_state = state
        else:
            # FIXME: self._initial_state is deprecated. This branch will be removed soon
            state = self._initial_state.copy()
            state.history.jumpkind = jumpkind
            self._reset_state_mode(state, "fastpath")
            state._ip = state.solver.BVV(ip, self.project.arch.bits)

        if jumpkind is not None:
            state.history.jumpkind = jumpkind

        # THIS IS A HACK FOR MIPS
        if ip is not None and self.project.arch.name in ("MIPS32", "MIPS64"):
            # We assume this is a function start
            state.regs.t9 = ip
        # TODO there was at one point special logic for the ppc64 table of contents but it seems to have bitrotted

        return state

    def _get_one_pending_job(self):
        """
        Retrieve a pending job.

        :return: A CFGJob instance or None
        """

        pending_job_key = next(iter(self._pending_jobs.keys()))
        pending_job = self._pending_jobs[pending_job_key].pop()
        if len(self._pending_jobs[pending_job_key]) == 0:
            del self._pending_jobs[pending_job_key]

        pending_job_state = pending_job.state
        pending_job_call_stack = pending_job.call_stack
        pending_job_src_block_id = pending_job.src_block_id
        pending_job_src_exit_stmt_idx = pending_job.src_exit_stmt_idx

        self._deregister_analysis_job(pending_job.caller_func_addr, pending_job)

        # Let's check whether this address has been traced before.
        if pending_job_key in self._nodes:
            node = self._nodes[pending_job_key]
            if node in self.graph:
                pending_exit_addr = self._block_id_addr(pending_job_key)
                # That block has been traced before. Let's forget about it
                l.debug("Target 0x%08x has been traced before. Trying the next one...", pending_exit_addr)

                # However, we should still create the FakeRet edge
                self._graph_add_edge(
                    pending_job_src_block_id,
                    pending_job_key,
                    jumpkind="Ijk_FakeRet",
                    stmt_idx=pending_job_src_exit_stmt_idx,
                    ins_addr=pending_job.src_exit_ins_addr,
                )

                return None

        pending_job_state.history.jumpkind = "Ijk_FakeRet"

        job = CFGJob(
            pending_job_state.addr,
            pending_job_state,
            self._context_sensitivity_level,
            src_block_id=pending_job_src_block_id,
            src_exit_stmt_idx=pending_job_src_exit_stmt_idx,
            src_ins_addr=pending_job.src_exit_ins_addr,
            call_stack=pending_job_call_stack,
        )
        l.debug("Tracing a missing return exit %s", self._block_id_repr(pending_job_key))

        return job

    def _process_hints(self, analyzed_addrs):
        """
        Process function hints in the binary.

        :return: None
        """

        # Function hints!
        # Now let's see how many new functions we can get here...
        while self._pending_function_hints:
            f = self._pending_function_hints.pop()
            if f not in analyzed_addrs:
                new_state = self.project.factory.entry_state(mode="fastpath")
                new_state.ip = new_state.solver.BVV(f, self.project.arch.bits)

                # TOOD: Specially for MIPS
                if new_state.arch.name in ("MIPS32", "MIPS64"):
                    # Properly set t9
                    new_state.registers.store("t9", f)

                new_path_wrapper = CFGJob(f, new_state, self._context_sensitivity_level)
                self._insert_job(new_path_wrapper)
                self._register_analysis_job(f, new_path_wrapper)
                l.debug("Picking a function 0x%x from pending function hints.", f)
                self.kb.functions.function(new_path_wrapper.func_addr, create=True)
                break

    def _post_analysis(self):
        """
        Post-CFG-construction.

        :return: None
        """

        self._make_completed_functions()
        new_changes = self._iteratively_analyze_function_features()
        functions_do_not_return = new_changes["functions_do_not_return"]
        self._update_function_callsites(functions_do_not_return)

        # Create all pending edges
        for _, edges in self._pending_edges.items():
            for src_node, dst_node, data in edges:
                self._graph_add_edge(src_node, dst_node, **data)

        # Remove those edges that will never be taken!
        self._remove_non_return_edges()

        CFGBase._post_analysis(self)

    # Job handling

    def _pre_job_handling(self, job):  # pylint:disable=arguments-differ
        """
        Before processing a CFGJob.
        Right now each block is traced at most once. If it is traced more than once, we will mark it as "should_skip"
        before tracing it.
        An AngrForwardAnalysisSkipJob exception is raised in order to skip analyzing the job.

        :param CFGJob job: The CFG job object.
        :param dict _locals: A bunch of local variables that will be kept around when handling this job and its
                        corresponding successors.
        :return: None
        """

        # Extract initial info the CFGJob
        job.call_stack_suffix = job.get_call_stack_suffix()
        job.current_function = self.kb.functions.function(
            job.func_addr, create=True, syscall=job.jumpkind.startswith("Ijk_Sys")
        )
        src_block_id = job.src_block_id
        src_exit_stmt_idx = job.src_exit_stmt_idx
        src_ins_addr = job.src_ins_addr
        addr = job.addr

        # Log this address
        if l.level == logging.DEBUG:
            self._analyzed_addrs.add(addr)

        if addr == job.func_addr:
            # Store the input state of this function
            self._function_input_states[job.func_addr] = job.state

        # deregister this job
        self._deregister_analysis_job(job.func_addr, job)

        # Generate a unique key for this job
        block_id = job.block_id

        # Should we skip tracing this block?
        should_skip = False
        if self._traced_addrs[job.call_stack_suffix][addr] >= self._max_iterations:
            should_skip = True
        elif (
            self._is_call_jumpkind(job.jumpkind)
            and self._call_depth is not None
            and len(job.call_stack) > self._call_depth
            and (self._call_tracing_filter is None or self._call_tracing_filter(job.state, job.jumpkind))
        ):
            should_skip = True

        # SimInspect breakpoints support
        job.state._inspect("cfg_handle_job", BP_BEFORE)

        # Get a SimSuccessors out of current job
        sim_successors, exception_info, _ = self._get_simsuccessors(addr, job, current_function_addr=job.func_addr)

        # determine the depth of this basic block
        if self._max_steps is None:
            # it's unnecessary to track depth when we are not limiting max_steps
            depth = None
        else:
            if src_block_id is None:
                # oh this is the very first basic block on this path
                depth = 0
            else:
                src_cfgnode = self._nodes[src_block_id]
                depth = src_cfgnode.depth + 1
                # the depth will not be updated later on even if this block has a greater depth on another path.
                # consequently, the `max_steps` limit is not veyr precise - I didn't see a need to make it precise
                # though.

        if block_id not in self._nodes:
            # Create the CFGNode object
            cfg_node = self._create_cfgnode(
                sim_successors, job.call_stack, job.func_addr, block_id=block_id, depth=depth
            )

            self._model.add_node(block_id, cfg_node)

        else:
            # each block_id should only correspond to one CFGNode
            # use the existing CFGNode object
            # note that since we reuse existing CFGNodes, we may miss the following cases:
            #
            # mov eax, label_0       mov ebx, label_1
            #     jmp xxx                 jmp xxx
            #         |                      |
            #         |                      |
            #         *----------------------*
            #                     |
            #                 call eax
            #
            # Since the basic block "call eax" will only be traced once, either label_0 or label_1 will be missed in
            # this case. Indirect jump resolution might be able to get it, but that's another story. Ideally,
            # "call eax" should be traced twice with *different* sim_successors keys, which requires block ID being flow
            # sensitive, but it is way too expensive.

            cfg_node = self._nodes[block_id]

        # Increment tracing count for this block
        self._traced_addrs[job.call_stack_suffix][addr] += 1

        if self._keep_state:
            # TODO: if we are reusing an existing CFGNode, we will be overwriting the original input state here. we
            # TODO: should save them all, which, unfortunately, requires some redesigning :-(
            cfg_node.input_state = sim_successors.initial_state

        # See if this job cancels another FakeRet
        # This should be done regardless of whether this job should be skipped or not, otherwise edges will go missing
        # in the CFG or function transition graphs.
        if job.jumpkind == "Ijk_FakeRet" or (job.jumpkind == "Ijk_Ret" and block_id in self._pending_jobs):
            # The fake ret is confirmed (since we are returning from the function it calls). Create an edge for it
            # in the graph.

            the_jobs = []
            if block_id in self._pending_jobs:
                the_jobs: "PendingJob" = self._pending_jobs.pop(block_id)
                for the_job in the_jobs:
                    self._deregister_analysis_job(the_job.caller_func_addr, the_job)
            else:
                the_jobs = [job]

            for the_job in the_jobs:
                self._graph_add_edge(
                    the_job.src_block_id,
                    block_id,
                    jumpkind="Ijk_FakeRet",
                    stmt_idx=the_job.src_exit_stmt_idx,
                    ins_addr=src_ins_addr,
                )
                self._update_function_transition_graph(
                    the_job.src_block_id,
                    block_id,
                    jumpkind="Ijk_FakeRet",
                    ins_addr=src_ins_addr,
                    stmt_idx=the_job.src_exit_stmt_idx,
                    confirmed=True,
                )

        if sim_successors is None or should_skip:
            # We cannot retrieve the block, or we should skip the analysis of this node
            # But we create the edge anyway. If the sim_successors does not exist, it will be an edge from the previous
            # node to a PathTerminator
            self._graph_add_edge(
                src_block_id, block_id, jumpkind=job.jumpkind, stmt_idx=src_exit_stmt_idx, ins_addr=src_ins_addr
            )
            self._update_function_transition_graph(
                src_block_id, block_id, jumpkind=job.jumpkind, ins_addr=src_ins_addr, stmt_idx=src_exit_stmt_idx
            )

            # We are good. Raise the exception and leave
            raise AngrSkipJobNotice()

        self._update_thumb_addrs(sim_successors, job.state)

        # We store the function hints first. Function hints will be checked at the end of the analysis to avoid
        # any duplication with existing jumping targets
        if self._enable_function_hints:
            if sim_successors.sort == "IRSB" and sim_successors.all_successors:
                function_hints = self._search_for_function_hints(sim_successors.all_successors[0])
                for f in function_hints:
                    self._pending_function_hints.add(f)

        self._graph_add_edge(
            src_block_id, block_id, jumpkind=job.jumpkind, stmt_idx=src_exit_stmt_idx, ins_addr=src_ins_addr
        )
        self._update_function_transition_graph(
            src_block_id, block_id, jumpkind=job.jumpkind, ins_addr=src_ins_addr, stmt_idx=src_exit_stmt_idx
        )

        if block_id in self._pending_edges:
            # there are some edges waiting to be created. do it here.
            for src_key, dst_key, data in self._pending_edges[block_id]:
                self._graph_add_edge(src_key, dst_key, **data)
            del self._pending_edges[block_id]

        block_info = {
            reg: sim_successors.initial_state.registers.load(reg) for reg in self.project.arch.persistent_regs
        }
        self._block_artifacts[addr] = block_info

        job.cfg_node = cfg_node
        job.sim_successors = sim_successors
        job.exception_info = exception_info

        # For debugging purposes!
        job.successor_status = {}

    def _get_successors(self, job):
        """
        Get a collection of successors out of the current job.

        :param CFGJob job:  The CFGJob instance.
        :return:            A collection of successors.
        :rtype:             list
        """

        addr = job.addr
        sim_successors = job.sim_successors
        cfg_node = job.cfg_node
        input_state = job.state
        func_addr = job.func_addr

        # check step limit
        if self._max_steps is not None:
            depth = cfg_node.depth
            if depth >= self._max_steps:
                return []

        successors = []
        is_indirect_jump = sim_successors.sort == "IRSB" and self._is_indirect_jump(cfg_node, sim_successors)
        indirect_jump_resolved_by_resolvers = False

        if is_indirect_jump and self._resolve_indirect_jumps:
            # Try to resolve indirect jumps
            irsb = input_state.block(cross_insn_opt=False).vex

            resolved, resolved_targets, ij = self._indirect_jump_encountered(
                addr, cfg_node, irsb, func_addr, stmt_idx=DEFAULT_STATEMENT
            )
            if resolved:
                successors = self._convert_indirect_jump_targets_to_states(job, resolved_targets)
                if ij:
                    self._indirect_jump_resolved(ij, ij.addr, None, resolved_targets)
            else:
                # Try to resolve this indirect jump using heavier approaches
                resolved_targets = self._process_one_indirect_jump(ij, func_graph_complete=False)
                successors = self._convert_indirect_jump_targets_to_states(job, resolved_targets)

            if successors:
                indirect_jump_resolved_by_resolvers = True
            else:
                # It's unresolved. Add it to the wait list (but apparently we don't have any better way to resolve it
                # right now).
                self._indirect_jumps_to_resolve.add(ij)

        if not successors:
            # Get all successors of this block
            successors = (
                (sim_successors.flat_successors + sim_successors.unsat_successors)
                if addr not in self._avoid_runs
                else []
            )

        # Post-process successors
        successors, job.extra_info = self._post_process_successors(input_state, sim_successors, successors)

        all_successors = successors + sim_successors.unconstrained_successors

        # make sure FakeRets are at the last
        all_successors = [suc for suc in all_successors if suc.history.jumpkind != "Ijk_FakeRet"] + [
            suc for suc in all_successors if suc.history.jumpkind == "Ijk_FakeRet"
        ]

        if self._keep_state:
            cfg_node.final_states = all_successors[::]

        if is_indirect_jump and not indirect_jump_resolved_by_resolvers:
            # For indirect jumps, filter successors that do not make sense
            successors = self._filter_insane_successors(successors)

        successors = self._try_resolving_indirect_jumps(
            sim_successors, cfg_node, func_addr, successors, job.exception_info, self._block_artifacts
        )
        # Remove all successors whose IP is symbolic
        successors = [s for s in successors if not s.ip.symbolic]

        # Add additional edges supplied by the user
        successors = self._add_additional_edges(input_state, sim_successors, cfg_node, successors)

        # if base graph is used, add successors implied from the graph
        if self._base_graph:
            basegraph_successor_addrs = set()
            for src_, dst_ in self._base_graph.edges():
                if src_.addr == addr:
                    basegraph_successor_addrs.add(dst_.addr)
            successor_addrs = {s.solver.eval(s.ip) for s in successors}
            extra_successor_addrs = basegraph_successor_addrs - successor_addrs

            if all_successors:  # make sure we have a base state to use
                base_state = all_successors[0]  # TODO: for calls, we want to use the fake_ret state

                for s_addr in extra_successor_addrs:
                    # an extra target
                    successor_state = base_state.copy()
                    successor_state.ip = s_addr
                    successors.append(successor_state)
            else:
                if extra_successor_addrs:
                    l.error("CFGEmulated terminates at %#x although base graph provided more exits.", addr)

        if not successors:
            # There is no way out :-(
            # Log it first
            self._push_unresolvable_run(addr)

            if sim_successors.sort == "SimProcedure" and isinstance(
                sim_successors.artifacts["procedure"], SIM_PROCEDURES["stubs"]["PathTerminator"]
            ):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it return to its call-site. However,
                # we don't want to use its state anymore as it might be corrupted.
                # Just create an edge in the graph.
                return_target = job.call_stack.current_return_target
                if return_target is not None:
                    new_call_stack = job.call_stack_copy()
                    return_target_key = self._generate_block_id(
                        new_call_stack.stack_suffix(self.context_sensitivity_level), return_target, False
                    )  # You can never return to a syscall

                    if not cfg_node.instruction_addrs:
                        ret_ins_addr = None
                    else:
                        if self.project.arch.branch_delay_slot:
                            if len(cfg_node.instruction_addrs) > 1:
                                ret_ins_addr = cfg_node.instruction_addrs[-2]
                            else:
                                l.error("At %s: expecting more than one instruction. Only got one.", cfg_node)
                                ret_ins_addr = None
                        else:
                            ret_ins_addr = cfg_node.instruction_addrs[-1]

                    # Things might be a bit difficult here. _graph_add_edge() requires both nodes to exist, but here
                    # the return target node may not exist yet. If that's the case, we will put it into a "delayed edge
                    # list", and add this edge later when the return target CFGNode is created.
                    if return_target_key in self._nodes:
                        self._graph_add_edge(
                            job.block_id,
                            return_target_key,
                            jumpkind="Ijk_Ret",
                            stmt_id=DEFAULT_STATEMENT,
                            ins_addr=ret_ins_addr,
                        )
                    else:
                        self._pending_edges[return_target_key].append(
                            (
                                job.block_id,
                                return_target_key,
                                {
                                    "jumpkind": "Ijk_Ret",
                                    "stmt_id": DEFAULT_STATEMENT,
                                    "ins_addr": ret_ins_addr,
                                },
                            )
                        )

            else:
                # There are no successors, but we still want to update the function graph
                artifacts = job.sim_successors.artifacts
                if "irsb" in artifacts and "insn_addrs" in artifacts and artifacts["insn_addrs"]:
                    the_irsb = artifacts["irsb"]
                    insn_addrs = artifacts["insn_addrs"]
                    self._handle_job_without_successors(job, the_irsb, insn_addrs)

        # TODO: replace it with a DDG-based function IO analysis
        # handle all actions
        if successors:
            self._handle_actions(
                successors[0],
                sim_successors,
                job.current_function,
                job.current_stack_pointer,
                set(),
            )

        return successors

    def _post_job_handling(self, job: CFGJob, _new_jobs, successors: List[SimState]):  # type: ignore[override]
        """

        :param CFGJob job:
        :param successors:
        :return:
        """

        # Finally, post-process CFG Node and log the return target
        if job.extra_info:
            if job.extra_info["is_call_jump"] and job.extra_info["return_target"] is not None:
                job.cfg_node.return_target = job.extra_info["return_target"]

        # Debugging output if needed
        if l.level == logging.DEBUG:
            # Only in DEBUG mode do we process and output all those shit
            self._post_handle_job_debug(job, successors)

        # SimInspect breakpoints support
        job.state._inspect("cfg_handle_job", BP_AFTER)

    def _post_process_successors(self, input_state, sim_successors, successors):
        """
        Filter the list of successors

        :param SimState      input_state:            Input state.
        :param SimSuccessors sim_successors:         The SimSuccessors instance.
        :param list successors:                      A list of successors generated after processing the current block.
        :return:                                     A list of successors.
        :rtype:                                      list
        """

        if sim_successors.sort == "IRSB" and input_state.thumb:
            successors = self._arm_thumb_filter_jump_successors(
                sim_successors.artifacts["irsb"],
                successors,
                lambda state: state.scratch.ins_addr,
                lambda state: state.scratch.exit_stmt_idx,
                lambda state: state.history.jumpkind,
            )

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_FakeRet, and Ijk_Call always goes first
        extra_info = {
            "is_call_jump": False,
            "call_target": None,
            "return_target": None,
            "last_call_exit_target": None,
            "skip_fakeret": False,
        }

        # Post-process jumpkind before touching all_successors
        for (
            suc
        ) in sim_successors.all_successors:  # we process all successors here to include potential unsat successors
            suc_jumpkind = suc.history.jumpkind
            if self._is_call_jumpkind(suc_jumpkind):
                extra_info["is_call_jump"] = True
                break

        return successors, extra_info

    def _post_handle_job_debug(self, job: CFGJob, successors: List[SimState]) -> None:
        """
        Post job handling: print debugging information regarding the current job.

        :param CFGJob job:      The current CFGJob instance.
        :param list successors: All successors of the analysis job.
        :return: None
        """

        sim_successors = job.sim_successors
        call_stack_suffix = job.call_stack_suffix
        extra_info = job.extra_info
        successor_status = job.successor_status

        func = self.project.loader.find_symbol(job.func_addr)
        obj = self.project.loader.find_object_containing(job.addr)
        function_name = func.name if func is not None else None
        module_name = obj.provides if obj is not None else None

        node = self.model.get_node(job.block_id)
        depth_str = "(D:%s)" % node.depth if node.depth is not None else ""

        l.debug(
            "%s [%#x%s | %s]",
            sim_successors.description,
            sim_successors.addr,
            depth_str,
            "->".join([hex(i) for i in call_stack_suffix if i is not None]),
        )
        l.debug("(Function %s of binary %s)", function_name, module_name)
        l.debug("|    Call jump: %s", extra_info["is_call_jump"] if extra_info is not None else "unknown")

        for suc in successors:
            jumpkind = suc.history.jumpkind
            if jumpkind == "Ijk_FakeRet":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug(
                    "|    target: %#x %s [%s] %s",
                    suc.solver.eval_one(suc.ip),
                    successor_status[suc],
                    exit_type_str,
                    jumpkind,
                )
            except (SimValueError, SimSolverModeError):
                l.debug("|    target cannot be concretized. %s [%s] %s", successor_status[suc], exit_type_str, jumpkind)
        l.debug("%d exits remaining, %d exits pending.", len(self._job_info_queue), len(self._pending_jobs))
        l.debug("%d unique basic blocks are analyzed so far.", len(self._analyzed_addrs))

    def _iteratively_clean_pending_exits(self):
        """
        Iteratively update the completed functions set, analyze whether each function returns or not, and remove
        pending exits if the callee function does not return. We do this iteratively so that we come to a fixed point
        in the end. In most cases, the number of outer iteration equals to the maximum levels of wrapped functions
        whose "returningness" is determined by the very last function it calls.

        :return: None
        """

        while True:
            # did we finish analyzing any function?
            # fill in self._completed_functions
            self._make_completed_functions()

            if self._pending_jobs:
                # There are no more remaining jobs, but only pending jobs left. Each pending job corresponds to
                # a previous job that does not return properly.
                # Now it's a good time to analyze each function (that we have so far) and determine if it is a)
                # returning, b) not returning, or c) unknown. For those functions that are definitely not returning,
                # remove the corresponding pending exits from `pending_jobs` array. Perform this procedure iteratively
                # until no new not-returning functions appear. Then we pick a pending exit based on the following
                # priorities:
                # - Job pended by a returning function
                # - Job pended by an unknown function

                new_changes = self._iteratively_analyze_function_features()
                functions_do_not_return = new_changes["functions_do_not_return"]

                self._update_function_callsites(functions_do_not_return)

                if not self._clean_pending_exits():
                    # no more pending exits are removed. we are good to go!
                    break
            else:
                break

    def _clean_pending_exits(self):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning syscalls
        c) they are the return exits of non-returning functions

        :return: True if any pending exits are removed, False otherwise
        :rtype: bool
        """

        pending_exits_to_remove = []

        for block_id, jobs in self._pending_jobs.items():
            for pe in jobs:
                if pe.returning_source is None:
                    # The original call failed. This pending exit must be followed.
                    continue

                func = self.kb.functions.function(pe.returning_source)
                if func is None:
                    # Why does it happen?
                    l.warning(
                        "An expected function at %s is not found. Please report it to Fish.",
                        hex(pe.returning_source) if pe.returning_source is not None else "None",
                    )
                    continue

                if func.returning is False:
                    # Oops, it's not returning
                    # Remove this pending exit
                    pending_exits_to_remove.append(block_id)

                    # We want to mark that call as not returning in the current function
                    current_function_addr = self._block_id_current_func_addr(block_id)
                    if current_function_addr is not None:
                        current_function = self.kb.functions.function(current_function_addr)
                        if current_function is not None:
                            call_site_addr = self._block_id_addr(pe.src_block_id)
                            current_function._call_sites[call_site_addr] = (func.addr, None)
                        else:
                            l.warning(
                                "An expected function at %#x is not found. Please report it to Fish.",
                                current_function_addr,
                            )

        for block_id in pending_exits_to_remove:
            l.debug(
                "Removing all pending exits to %#x since the target function %#x does not return",
                self._block_id_addr(block_id),
                next(iter(self._pending_jobs[block_id])).returning_source,
            )

            for to_remove in self._pending_jobs[block_id]:
                self._deregister_analysis_job(to_remove.caller_func_addr, to_remove)

            del self._pending_jobs[block_id]

        if pending_exits_to_remove:
            return True
        return False

    # Successor handling

    def _pre_handle_successor_state(self, extra_info, jumpkind, target_addr):
        """

        :return: None
        """

        # Fill up extra_info
        if extra_info["is_call_jump"] and self._is_call_jumpkind(jumpkind):
            extra_info["call_target"] = target_addr

        if extra_info["is_call_jump"] and jumpkind == "Ijk_FakeRet":
            extra_info["return_target"] = target_addr

        if jumpkind == "Ijk_Call":
            extra_info["last_call_exit_target"] = target_addr

    def _handle_successor(self, job, successor: SimState, successors):
        """
        Returns a new CFGJob instance for further analysis, or None if there is no immediate state to perform the
        analysis on.

        :param CFGJob job: The current job.
        """

        state: SimState = successor
        all_successor_states = successors
        addr = job.addr

        # The PathWrapper instance to return
        pw = None

        job.successor_status[state] = ""

        new_state = state.copy()
        suc_jumpkind = state.history.jumpkind
        suc_exit_stmt_idx = state.scratch.exit_stmt_idx
        suc_exit_ins_addr = state.scratch.exit_ins_addr

        if suc_jumpkind in {
            "Ijk_EmWarn",
            "Ijk_NoDecode",
            "Ijk_MapFail",
            "Ijk_NoRedir",
            "Ijk_SigTRAP",
            "Ijk_SigSEGV",
            "Ijk_ClientReq",
        }:
            # Ignore SimExits that are of these jumpkinds
            job.successor_status[state] = "Skipped"
            return []

        call_target = job.extra_info["call_target"]
        if suc_jumpkind == "Ijk_FakeRet" and call_target is not None:
            # if the call points to a SimProcedure that doesn't return, we don't follow the fakeret anymore
            if self.project.is_hooked(call_target):
                sim_proc = self.project._sim_procedures[call_target]
                if sim_proc.NO_RET:
                    return []

        # Get target address
        try:
            target_addr = state.solver.eval_one(state.ip)
        except (SimValueError, SimSolverModeError):
            # It cannot be concretized currently. Maybe we can handle it later, maybe it just cannot be concretized
            target_addr = None
            if suc_jumpkind == "Ijk_Ret":
                target_addr = job.call_stack.current_return_target
                if target_addr is not None:
                    new_state.ip = new_state.solver.BVV(target_addr, new_state.arch.bits)

        if target_addr is None:
            # Unlucky...
            return []

        if state.thumb:
            # Make sure addresses are always odd. It is important to encode this information in the address for the
            # time being.
            target_addr |= 1

        # see if the target successor is in our whitelist
        if self._address_whitelist is not None:
            if target_addr not in self._address_whitelist:
                l.debug("Successor %#x is not in the address whitelist. Skip.", target_addr)
                return []

        # see if this edge is in the base graph
        if self._base_graph is not None:
            # TODO: make it more efficient. the current implementation is half-assed and extremely slow
            for src_, dst_ in self._base_graph.edges():
                if src_.addr == addr and dst_.addr == target_addr:
                    break
            else:
                # not found
                l.debug("Edge (%#x -> %#x) is not found in the base graph. Skip.", addr, target_addr)
                return []

        # Fix target_addr for syscalls
        if suc_jumpkind.startswith("Ijk_Sys"):
            syscall_proc = self.project.simos.syscall(new_state)
            if syscall_proc is not None:
                target_addr = syscall_proc.addr

        self._pre_handle_successor_state(job.extra_info, suc_jumpkind, target_addr)

        if suc_jumpkind == "Ijk_FakeRet":
            if target_addr == job.extra_info["last_call_exit_target"]:
                l.debug("... skipping a fake return exit that has the same target with its call exit.")
                job.successor_status[state] = "Skipped"
                return []

            if job.extra_info["skip_fakeret"]:
                l.debug("... skipping a fake return exit since the function it's calling doesn't return")
                job.successor_status[state] = "Skipped - non-returning function 0x%x" % job.extra_info["call_target"]
                return []

        # TODO: Make it optional
        if suc_jumpkind == "Ijk_Ret" and self._call_depth is not None and len(job.call_stack) <= 1:
            # We cannot continue anymore since this is the end of the function where we started tracing
            l.debug("... reaching the end of the starting function, skip.")
            job.successor_status[state] = "Skipped - reaching the end of the starting function"
            return []

        # Create the new call stack of target block
        new_call_stack = self._create_new_call_stack(addr, all_successor_states, job, target_addr, suc_jumpkind)
        # Create the callstack suffix
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        # Tuple that will be used to index this exit
        new_tpl = self._generate_block_id(new_call_stack_suffix, target_addr, suc_jumpkind.startswith("Ijk_Sys"))

        # We might have changed the mode for this basic block
        # before. Make sure it is still running in 'fastpath' mode
        self._reset_state_mode(new_state, "fastpath")

        pw = CFGJob(
            target_addr,
            new_state,
            self._context_sensitivity_level,
            src_block_id=job.block_id,
            src_exit_stmt_idx=suc_exit_stmt_idx,
            src_ins_addr=suc_exit_ins_addr,
            call_stack=new_call_stack,
            jumpkind=suc_jumpkind,
        )
        # Special case: If the binary has symbols and the target address is a function, but for some reason (e.g.,
        # a tail-call optimization) the CallStack's function address is still the old function address, we will have to
        # overwrite it here.
        if not self._is_call_jumpkind(pw.jumpkind):
            target_symbol = self.project.loader.find_symbol(target_addr)
            if target_symbol and target_symbol.is_function:
                # Force update the function address
                pw.func_addr = target_addr

        # Generate new exits
        if suc_jumpkind == "Ijk_Ret":
            # This is the real return exit
            job.successor_status[state] = "Appended"

        elif suc_jumpkind == "Ijk_FakeRet":
            # This is the default "fake" retn that generated at each
            # call. Save them first, but don't process them right
            # away
            # st = self.project._simos.prepare_call_state(new_state, initial_state=saved_state)
            st = new_state
            self._reset_state_mode(st, "fastpath")

            pw = None  # clear the job
            pe = PendingJob(
                job.func_addr,
                job.extra_info["call_target"],
                st,
                job.block_id,
                suc_exit_stmt_idx,
                suc_exit_ins_addr,
                new_call_stack,
            )
            self._pending_jobs[new_tpl].append(pe)
            self._register_analysis_job(pe.caller_func_addr, pe)
            job.successor_status[state] = "Pended"

        elif self._traced_addrs[new_call_stack_suffix][target_addr] >= 1 and suc_jumpkind == "Ijk_Ret":
            # This is a corner case for the f****** ARM instruction
            # like
            # BLEQ <address>
            # If we have analyzed the boring exit before returning from that called address, we will lose the link
            # between the last block of the function being called and the basic block it returns to. We cannot
            # reanalyze the basic block as we are not flow-sensitive, but we can still record the connection and make
            # for it afterwards.
            pass

        else:
            job.successor_status[state] = "Appended"

        if job.extra_info["is_call_jump"] and job.extra_info["call_target"] in self._non_returning_functions:
            job.extra_info["skip_fakeret"] = True

        if not pw:
            return []

        # register the job
        self._register_analysis_job(pw.func_addr, pw)

        return [pw]

    def _handle_job_without_successors(self, job, irsb, insn_addrs):
        """
        A block without successors should still be handled so it can be added to the function graph correctly.

        :param CFGJob job:  The current job that do not have any successor.
        :param IRSB irsb:   The related IRSB.
        :param insn_addrs:  A list of instruction addresses of this IRSB.
        :return: None
        """

        # it's not an empty block

        # handle all conditional exits
        ins_addr = job.addr
        for stmt_idx, stmt in enumerate(irsb.statements):
            if type(stmt) is pyvex.IRStmt.IMark:
                ins_addr = stmt.addr + stmt.delta
            elif type(stmt) is pyvex.IRStmt.Exit:
                successor_jumpkind = stmt.jk
                self._update_function_transition_graph(
                    job.block_id,
                    None,
                    jumpkind=successor_jumpkind,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                )

        # handle the default exit
        successor_jumpkind = irsb.jumpkind
        successor_last_ins_addr = insn_addrs[-1]
        self._update_function_transition_graph(
            job.block_id,
            None,
            jumpkind=successor_jumpkind,
            ins_addr=successor_last_ins_addr,
            stmt_idx=DEFAULT_STATEMENT,
        )

    # SimAction handling

    def _handle_actions(self, state, current_run, func, sp_addr, accessed_registers):
        """
        For a given state and current location of of execution, will update a function by adding the offets of
        appropriate actions to the stack variable or argument registers for the fnc.

        :param SimState state: upcoming state.
        :param SimSuccessors current_run: possible result states.
        :param knowledge.Function func: current function.
        :param int sp_addr: stack pointer address.
        :param set accessed_registers: set of before accessed registers.
        """
        se = state.solver

        if func is not None and sp_addr is not None:
            # Fix the stack pointer (for example, skip the return address on the stack)
            new_sp_addr = sp_addr + self.project.arch.call_sp_fix

            actions = [a for a in state.history.recent_actions if a.bbl_addr == current_run.addr]

            for a in actions:
                if a.type == "mem" and a.action == "read":
                    try:
                        addr = se.eval_one(a.addr.ast, default=0)
                    except (claripy.ClaripyError, SimSolverModeError):
                        continue
                    if (self.project.arch.call_pushes_ret and addr >= new_sp_addr) or (
                        not self.project.arch.call_pushes_ret and addr >= new_sp_addr
                    ):
                        # TODO: What if a variable locates higher than the stack is modified as well? We probably want
                        # TODO: to make sure the accessing address falls in the range of stack
                        offset = addr - new_sp_addr
                        func._add_argument_stack_variable(offset)
                elif a.type == "reg":
                    offset = a.offset
                    if a.action == "read" and offset not in accessed_registers:
                        func._add_argument_register(offset)
                    elif a.action == "write":
                        accessed_registers.add(offset)
        else:
            l.error(
                "handle_actions: Function not found, or stack pointer is None. It might indicates unbalanced stack."
            )

    # Private utils - DiGraph construction and manipulation

    def _graph_get_node(self, node_key, terminator_for_nonexistent_node=False):
        """

        :param node_key:
        :return:
        """

        if node_key not in self._nodes:
            if not terminator_for_nonexistent_node:
                return None
            # Generate a PathTerminator node
            addr = self._block_id_addr(node_key)
            func_addr = self._block_id_current_func_addr(node_key)
            if func_addr is None:
                # We'll have to use the current block address instead
                # TODO: Is it really OK?
                func_addr = self._block_id_addr(node_key)

            is_thumb = isinstance(self.project.arch, ArchARM) and addr % 2 == 1

            pt = CFGENode(
                self._block_id_addr(node_key),
                None,
                self.model,
                input_state=None,
                simprocedure_name="PathTerminator",
                function_address=func_addr,
                callstack_key=self._block_id_callstack_key(node_key),
                thumb=is_thumb,
            )
            if self._keep_state:
                # We don't have an input state available for it (otherwise we won't have to create a
                # PathTerminator). This is just a trick to make get_any_irsb() happy.
                pt.input_state = self.project.factory.entry_state()
                pt.input_state.ip = pt.addr
            self._model.add_node(node_key, pt)

            if is_thumb:
                self._thumb_addrs.add(addr)
                self._thumb_addrs.add(addr - 1)

            l.debug("Block ID %s does not exist. Create a PathTerminator instead.", self._block_id_repr(node_key))

        return self._nodes[node_key]

    def _graph_add_edge(self, src_node_key, dst_node_key, **kwargs):
        """

        :param src_node_key:
        :param dst_node_key:
        :param jumpkind:
        :param exit_stmt_idx:
        :return:
        """

        dst_node = self._graph_get_node(dst_node_key, terminator_for_nonexistent_node=True)

        if src_node_key is None:
            self.graph.add_node(dst_node)

        else:
            src_node = self._graph_get_node(src_node_key, terminator_for_nonexistent_node=True)
            self.graph.add_edge(src_node, dst_node, **kwargs)

    def _update_function_transition_graph(
        self, src_node_key, dst_node_key, jumpkind="Ijk_Boring", ins_addr=None, stmt_idx=None, confirmed=None
    ):
        """
        Update transition graphs of functions in function manager based on information passed in.

        :param src_node_key:    Node key of the source CFGNode. Might be None.
        :param dst_node:        Node key of the destination CFGNode. Might be None.
        :param str jumpkind:    Jump kind of this transition.
        :param int ret_addr:    The theoretical return address for calls.
        :param int or None ins_addr:    Address of the instruction where this transition is made.
        :param int or None stmt_idx:    ID of the statement where this transition is made.
        :param bool or None confirmed:  Whether this call transition has been confirmed or not.
        :return: None
        """

        if dst_node_key is not None:
            dst_node = self._graph_get_node(dst_node_key, terminator_for_nonexistent_node=True)
            dst_node_addr = dst_node.addr
            dst_codenode = dst_node.to_codenode()
            dst_node_func_addr = dst_node.function_address
        else:
            dst_node = None
            dst_node_addr = None
            dst_codenode = None
            dst_node_func_addr = None

        if src_node_key is None:
            if dst_node is None:
                raise ValueError("Either src_node_key or dst_node_key must be specified.")
            self.kb.functions.function(dst_node.function_address, create=True)._register_nodes(True, dst_codenode)
            return

        src_node = self._graph_get_node(src_node_key, terminator_for_nonexistent_node=True)

        # Update the transition graph of current function
        if jumpkind == "Ijk_Call":
            ret_addr = src_node.return_target
            ret_node = (
                self.kb.functions.function(src_node.function_address, create=True)._get_block(ret_addr).codenode
                if ret_addr
                else None
            )

            self.kb.functions._add_call_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_addr=dst_node_addr,
                retn_node=ret_node,
                syscall=False,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

        if jumpkind.startswith("Ijk_Sys"):
            self.kb.functions._add_call_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_addr=dst_node_addr,
                retn_node=src_node.to_codenode(),  # For syscalls, they are returning to the address of themselves
                syscall=True,
                ins_addr=ins_addr,
                stmt_idx=stmt_idx,
            )

        elif jumpkind == "Ijk_Ret":
            # Create a return site for current function
            self.kb.functions._add_return_from(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_node=dst_codenode,
            )

            if dst_node is not None:
                # Create a returning edge in the caller function
                self.kb.functions._add_return_from_call(
                    function_addr=dst_node_func_addr,
                    src_function_addr=src_node.function_address,
                    to_node=dst_codenode,
                )

        elif jumpkind == "Ijk_FakeRet":
            self.kb.functions._add_fakeret_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_node=dst_codenode,
                confirmed=confirmed,
            )

        elif jumpkind in ("Ijk_Boring", "Ijk_InvalICache"):
            src_obj = self.project.loader.find_object_containing(src_node.addr)
            dest_obj = self.project.loader.find_object_containing(dst_node.addr) if dst_node is not None else None

            if src_obj is dest_obj:
                # Jump/branch within the same object. Might be an outside jump.
                to_outside = src_node.function_address != dst_node_func_addr
            else:
                # Jump/branch between different objects. Must be an outside jump.
                to_outside = True

            if not to_outside:
                self.kb.functions._add_transition_to(
                    function_addr=src_node.function_address,
                    from_node=src_node.to_codenode(),
                    to_node=dst_codenode,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                )

            else:
                self.kb.functions._add_outside_transition_to(
                    function_addr=src_node.function_address,
                    from_node=src_node.to_codenode(),
                    to_node=dst_codenode,
                    to_function_addr=dst_node_func_addr,
                    ins_addr=ins_addr,
                    stmt_idx=stmt_idx,
                )

    def _update_function_callsites(self, noreturns):
        """
        Update the callsites of functions (remove return targets) that are calling functions that are just deemed not
        returning.

        :param iterable func_addrs: A collection of functions for newly-recovered non-returning functions.
        :return:                    None
        """

        for callee_func in noreturns:
            # consult the callgraph to find callers of each function
            if callee_func.addr not in self.functions.callgraph:
                continue
            caller_addrs = self.functions.callgraph.predecessors(callee_func.addr)
            for caller_addr in caller_addrs:
                caller = self.functions[caller_addr]
                if callee_func not in caller.transition_graph:
                    continue
                callsites = caller.transition_graph.predecessors(callee_func)
                for callsite in callsites:
                    caller._add_call_site(callsite.addr, callee_func.addr, None)

    def _add_additional_edges(self, input_state, sim_successors, cfg_node, successors):
        """

        :return:
        """

        # If we have additional edges for this block, add them in
        addr = cfg_node.addr

        if addr in self._additional_edges:
            dests = self._additional_edges[addr]
            for dst in dests:
                if sim_successors.sort == "IRSB":
                    base_state = sim_successors.all_successors[0].copy()
                else:
                    if successors:
                        # We try to use the first successor.
                        base_state = successors[0].copy()
                    else:
                        # The SimProcedure doesn't have any successor (e.g. it's a PathTerminator)
                        # We'll use its input state instead
                        base_state = input_state
                base_state.ip = dst
                # TODO: Allow for sp adjustments
                successors.append(base_state)
                l.debug("Additional jump target %#x for block %s is appended.", dst, sim_successors.description)

        return successors

    def _filter_insane_successors(self, successors):
        """
        Throw away all successors whose target doesn't make sense

        This method is called after we resolve an indirect jump using an unreliable method (like, not through one of
        the indirect jump resolvers, but through either pure concrete execution or backward slicing) to filter out the
        obviously incorrect successors.

        :param list successors: A collection of successors.
        :return:                A filtered list of successors
        :rtype:                 list
        """

        old_successors = successors[::]
        successors = []
        for i, suc in enumerate(old_successors):
            if suc.solver.symbolic(suc.ip):
                # It's symbolic. Take it, and hopefully we can resolve it later
                successors.append(suc)

            else:
                ip_int = suc.solver.eval_one(suc.ip)

                if (
                    self._is_address_executable(ip_int)
                    or self.project.is_hooked(ip_int)
                    or self.project.simos.is_syscall_addr(ip_int)
                ):
                    successors.append(suc)
                else:
                    l.debug(
                        "An obviously incorrect successor %d/%d (%#x) is ditched", i + 1, len(old_successors), ip_int
                    )

        return successors

    def _remove_non_return_edges(self):
        """
        Remove those return_from_call edges that actually do not return due to
        calling some not-returning functions.
        :return: None
        """
        for func in self.kb.functions.values():
            graph = func.transition_graph
            all_return_edges = [(u, v) for (u, v, data) in graph.edges(data=True) if data["type"] == "return"]
            for return_from_call_edge in all_return_edges:
                callsite_block_addr, return_to_addr = return_from_call_edge
                call_func_addr = func.get_call_target(callsite_block_addr)
                if call_func_addr is None:
                    continue

                call_func = self.kb.functions.function(call_func_addr)
                if call_func is None:
                    # Weird...
                    continue

                if call_func.returning is False:
                    # Remove that edge!
                    graph.remove_edge(call_func_addr, return_to_addr)
                    # Remove the edge in CFG
                    nodes = self.get_all_nodes(callsite_block_addr)
                    for n in nodes:
                        successors = self.get_successors_and_jumpkind(n, excluding_fakeret=False)
                        for successor, jumpkind in successors:
                            if jumpkind == "Ijk_FakeRet" and successor.addr == return_to_addr:
                                self.remove_edge(n, successor)

                                # Remove all dangling nodes
                                # wcc = list(networkx.weakly_connected_components(graph))
                                # for nodes in wcc:
                                #    if func.startpoint not in nodes:
                                #        graph.remove_nodes_from(nodes)

    # Private methods - resolving indirect jumps

    @staticmethod
    def _convert_indirect_jump_targets_to_states(job, indirect_jump_targets):
        """
        Convert each concrete indirect jump target into a SimState. If there are non-zero successors and the original
        jumpkind is a call, we also generate a fake-ret successor.

        :param job:                     The CFGJob instance.
        :param indirect_jump_targets:   A collection of concrete jump targets resolved from a indirect jump.
        :return:                        A list of SimStates.
        :rtype:                         list
        """

        first_successor = job.sim_successors.all_successors[0]
        successors = []
        for t in indirect_jump_targets:
            # Insert new successors
            a = first_successor.copy()
            a.ip = t
            successors.append(a)
        # special case: if the indirect jump is in fact an indirect call, we should create a FakeRet successor
        if successors and first_successor.history.jumpkind == "Ijk_Call":
            a = first_successor.copy()
            a.ip = job.cfg_node.addr + job.cfg_node.size
            a.history.jumpkind = "Ijk_FakeRet"
            successors.append(a)
        return successors

    def _try_resolving_indirect_jumps(self, sim_successors, cfg_node, func_addr, successors, exception_info, artifacts):
        """
        Resolve indirect jumps specified by sim_successors.addr.

        :param SimSuccessors sim_successors: The SimSuccessors instance.
        :param CFGNode cfg_node:                     The CFGNode instance.
        :param int func_addr:                        Current function address.
        :param list successors:                      A list of successors.
        :param tuple exception_info:                 The sys.exc_info() of the exception or None if none occurred.
        :param artifacts:                            A container of collected information.
        :return:                                     Resolved successors
        :rtype:                                      list
        """

        # Try to resolve indirect jumps with advanced backward slicing (if enabled)
        if sim_successors.sort == "IRSB" and self._is_indirect_jump(cfg_node, sim_successors):
            l.debug("IRSB %#x has an indirect jump as its default exit", cfg_node.addr)

            # We need input states to perform backward slicing
            if self._advanced_backward_slicing and self._keep_state:
                # Optimization: make sure we only try to resolve an indirect jump if any of the following criteria holds
                # - It's a jump (Ijk_Boring), and its target is either fully symbolic, or its resolved target is within
                #   the current binary
                # - It's a call (Ijk_Call), and its target is fully symbolic
                # TODO: This is very hackish, please refactor this part of code later
                should_resolve = True
                legit_successors = [
                    suc for suc in successors if suc.history.jumpkind in ("Ijk_Boring", "Ijk_InvalICache", "Ijk_Call")
                ]
                if legit_successors:
                    legit_successor = legit_successors[0]
                    if legit_successor.ip.symbolic:
                        if not legit_successor.history.jumpkind == "Ijk_Call":
                            should_resolve = False
                    else:
                        if legit_successor.history.jumpkind == "Ijk_Call":
                            should_resolve = False
                        else:
                            concrete_target = legit_successor.solver.eval(legit_successor.ip)
                            if (
                                self.project.loader.find_object_containing(concrete_target)
                                is not self.project.loader.main_object
                            ):
                                should_resolve = False

                else:
                    # No interesting successors... skip
                    should_resolve = False

                # TODO: Handle those successors
                if not should_resolve:
                    l.debug("This might not be an indirect jump that has multiple targets. Skipped.")
                    self.kb.unresolved_indirect_jumps.add(cfg_node.addr)

                else:
                    more_successors = self._backward_slice_indirect(cfg_node, sim_successors, func_addr)

                    if more_successors:
                        # Remove the symbolic successor
                        # TODO: Now we are removing all symbolic successors. Is it possible
                        # TODO: that there is more than one symbolic successor?
                        all_successors = [suc for suc in successors if not suc.solver.symbolic(suc.ip)]
                        # Insert new successors
                        # We insert new successors in the beginning of all_successors list so that we don't break the
                        # assumption that Ijk_FakeRet is always the last element in the list
                        for suc_addr in more_successors:
                            a = sim_successors.all_successors[0].copy()
                            a.ip = suc_addr
                            all_successors.insert(0, a)

                        l.debug("The indirect jump is successfully resolved.")
                        self.kb.indirect_jumps.update_resolved_addrs(cfg_node.addr, more_successors)

                    else:
                        l.debug("Failed to resolve the indirect jump.")
                        self.kb.unresolved_indirect_jumps.add(cfg_node.addr)

            else:
                if not successors:
                    l.debug("Cannot resolve the indirect jump without advanced backward slicing enabled: %s", cfg_node)

        # Try to find more successors if we failed to resolve the indirect jump before
        if exception_info is None and (cfg_node.is_simprocedure or self._is_indirect_jump(cfg_node, sim_successors)):
            has_call_jumps = any(suc_state.history.jumpkind == "Ijk_Call" for suc_state in successors)
            if has_call_jumps:
                concrete_successors = [
                    suc_state
                    for suc_state in successors
                    if suc_state.history.jumpkind != "Ijk_FakeRet" and not suc_state.solver.symbolic(suc_state.ip)
                ]
            else:
                concrete_successors = [
                    suc_state for suc_state in successors if not suc_state.solver.symbolic(suc_state.ip)
                ]
            symbolic_successors = [suc_state for suc_state in successors if suc_state.solver.symbolic(suc_state.ip)]

            resolved = not symbolic_successors
            if symbolic_successors:
                for suc in symbolic_successors:
                    if o.SYMBOLIC in suc.options:
                        targets = suc.solver.eval_upto(suc.ip, 32)
                        if len(targets) < 32:
                            all_successors = []
                            resolved = True
                            for t in targets:
                                new_ex = suc.copy()
                                new_ex.ip = suc.solver.BVV(t, suc.ip.size())
                                all_successors.append(new_ex)
                        else:
                            break

            if not resolved and (
                (symbolic_successors and not concrete_successors)
                or (not cfg_node.is_simprocedure and self._is_indirect_jump(cfg_node, sim_successors))
            ):
                l.debug("%s has an indirect jump. See what we can do about it.", cfg_node)

                if sim_successors.sort == "SimProcedure" and sim_successors.artifacts["adds_exits"]:
                    # Skip those SimProcedures that don't create new SimExits
                    l.debug(
                        "We got a SimProcedure %s in fastpath mode that creates new exits.", sim_successors.description
                    )
                    if self._enable_symbolic_back_traversal:
                        successors = self._symbolically_back_traverse(sim_successors, artifacts, cfg_node)
                        # mark jump as resolved if we got successors
                        if successors:
                            succ_addrs = [s.addr for s in successors]
                            self.kb.indirect_jumps.update_resolved_addrs(cfg_node.addr, succ_addrs)
                        else:
                            self.kb.unresolved_indirect_jumps.add(cfg_node.addr)
                        l.debug("Got %d concrete exits in symbolic mode.", len(successors))
                    else:
                        self.kb.unresolved_indirect_jumps.add(cfg_node.addr)
                        # keep fake_rets
                        successors = [s for s in successors if s.history.jumpkind == "Ijk_FakeRet"]

                elif sim_successors.sort == "IRSB" and any(ex.history.jumpkind != "Ijk_Ret" for ex in successors):
                    # We cannot properly handle Return as that requires us start execution from the caller...
                    l.debug("Try traversal backwards in symbolic mode on %s.", cfg_node)
                    if self._enable_symbolic_back_traversal:
                        successors = self._symbolically_back_traverse(sim_successors, artifacts, cfg_node)

                        # Remove successors whose IP doesn't make sense
                        successors = [
                            suc for suc in successors if self._is_address_executable(suc.solver.eval_one(suc.ip))
                        ]

                        # mark jump as resolved if we got successors
                        if successors:
                            succ_addrs = [s.addr for s in successors]
                            self.kb.indirect_jumps.update_resolved_addrs(cfg_node.addr, succ_addrs)
                        else:
                            self.kb.unresolved_indirect_jumps.add(cfg_node.addr)
                        l.debug("Got %d concrete exits in symbolic mode", len(successors))
                    else:
                        self.kb.unresolved_indirect_jumps.add(cfg_node.addr)
                        successors = []

                elif successors and all(ex.history.jumpkind == "Ijk_Ret" for ex in successors):
                    l.debug("All exits are returns (Ijk_Ret). It will be handled by pending exits.")

                else:
                    l.debug("Cannot resolve this indirect jump: %s", cfg_node)
                    self.kb.unresolved_indirect_jumps.add(cfg_node.addr)

        return successors

    def _backward_slice_indirect(self, cfgnode, sim_successors, current_function_addr):
        """
        Try to resolve an indirect jump by slicing backwards
        """
        # TODO: make this a real indirect jump resolver under the new paradigm

        irsb = sim_successors.artifacts["irsb"]  # shorthand

        l.debug("Resolving indirect jump at IRSB %s", irsb)

        # Let's slice backwards from the end of this exit
        next_tmp = irsb.next.tmp
        stmt_id = [i for i, s in enumerate(irsb.statements) if isinstance(s, pyvex.IRStmt.WrTmp) and s.tmp == next_tmp][
            0
        ]

        cdg = self.project.analyses[CDG].prep(fail_fast=self._fail_fast)(cfg=self)
        ddg = self.project.analyses[DDG].prep(fail_fast=self._fail_fast)(
            cfg=self, start=current_function_addr, call_depth=0
        )

        bc = self.project.analyses[BackwardSlice].prep(fail_fast=self._fail_fast)(
            self, cdg, ddg, targets=[(cfgnode, stmt_id)], same_function=True
        )
        taint_graph = bc.taint_graph
        # Find the correct taint
        next_nodes = [cl for cl in taint_graph.nodes() if cl.block_addr == sim_successors.addr]

        if not next_nodes:
            l.error("The target exit is not included in the slice. Something is wrong")
            return []

        next_node = next_nodes[0]

        # Get the weakly-connected subgraph that contains `next_node`
        all_subgraphs = (
            networkx.induced_subgraph(taint_graph, nodes) for nodes in networkx.weakly_connected_components(taint_graph)
        )
        starts = set()
        for subgraph in all_subgraphs:
            if next_node in subgraph:
                # Make sure there is no symbolic read...
                # FIXME: This is an over-approximation. We should try to limit the starts more
                nodes = [n for n in subgraph.nodes() if subgraph.in_degree(n) == 0]
                for n in nodes:
                    starts.add(n.block_addr)

        # Execute the slice
        successing_addresses = set()
        annotated_cfg = bc.annotated_cfg()
        for start in starts:
            l.debug("Start symbolic execution at 0x%x on program slice.", start)
            # Get the state from our CFG
            node = self.get_any_node(start)
            if node is None:
                # Well, we have to live with an empty state
                base_state = self.project.factory.blank_state(addr=start)
            else:
                base_state = node.input_state.copy()
                base_state.set_mode("symbolic")
                base_state.ip = start

                # Clear all initial taints (register values, memory values, etc.)
                initial_nodes = [n for n in bc.taint_graph.nodes() if bc.taint_graph.in_degree(n) == 0]
                for cl in initial_nodes:
                    # Iterate in all actions of this node, and pick corresponding actions
                    cfg_nodes = self.get_all_nodes(cl.block_addr)
                    for n in cfg_nodes:
                        if not n.final_states:
                            continue
                        actions = [
                            ac
                            for ac in n.final_states[0].history.recent_actions
                            # Normally it's enough to only use the first final state
                            if ac.bbl_addr == cl.block_addr and ac.stmt_idx == cl.stmt_idx
                        ]
                        for ac in actions:
                            if not hasattr(ac, "action"):
                                continue
                            if ac.action == "read":
                                if ac.type == "mem":
                                    unconstrained_value = base_state.solver.Unconstrained(
                                        "unconstrained", ac.size.ast * 8
                                    )
                                    base_state.memory.store(
                                        ac.addr, unconstrained_value, endness=self.project.arch.memory_endness
                                    )
                                elif ac.type == "reg":
                                    unconstrained_value = base_state.solver.Unconstrained(
                                        "unconstrained", ac.size.ast * 8
                                    )
                                    base_state.registers.store(
                                        ac.offset, unconstrained_value, endness=self.project.arch.register_endness
                                    )

                # Clear the constraints!
                base_state.release_plugin("solver")

            # For speed concerns, we are limiting the timeout for z3 solver to 5 seconds
            base_state.solver._solver.timeout = 5000

            sc = self.project.factory.simulation_manager(base_state)
            sc.use_technique(Slicecutor(annotated_cfg))
            sc.use_technique(LoopSeer(bound=1))
            sc.run()

            if sc.cut or sc.deadended:
                all_deadended_states = sc.cut + sc.deadended
                for s in all_deadended_states:
                    if s.addr == sim_successors.addr:
                        # We want to get its successors
                        succs = s.step()
                        for succ in succs.flat_successors:
                            successing_addresses.add(succ.addr)

            else:
                l.debug("Cannot determine the exit. You need some better ways to recover the exits :-(")

        l.debug("Resolution is done, and we have %d new successors.", len(successing_addresses))

        return list(successing_addresses)

    def _symbolically_back_traverse(self, current_block, block_artifacts, cfg_node):
        """
        Symbolically executes from ancestor nodes (2-5 times removed) finding paths of execution through the given
        CFGNode.

        :param SimSuccessors current_block: SimSuccessor with address to attempt to navigate to.
        :param dict block_artifacts:  Container of IRSB data - specifically used for known persistant register values.
        :param CFGNode cfg_node:      Current node interested around.
        :returns:                     Double-checked concrete successors.
        :rtype: List
        """

        class RegisterProtector:
            """
            A class that prevent specific registers from being overwritten.
            """

            def __init__(self, reg_offset, info_collection):
                """
                Class to overwrite registers.

                :param int reg_offest:       Register offset to overwrite from.
                :param dict info_collection: New register offsets to use (in container).
                """
                self._reg_offset = reg_offset
                self._info_collection = info_collection

            def write_persistent_register(self, state_):
                """
                Writes over given registers from self._info_collection (taken from block_artifacts)

                :param SimSuccessors state_: state to update registers for
                """
                if state_.inspect.address is None:
                    l.error("state.inspect.address is None. It will be fixed by Yan later.")
                    return

                if state_.registers.load(self._reg_offset).symbolic:
                    current_run = state_.inspect.address
                    if current_run in self._info_collection and not state_.solver.symbolic(
                        self._info_collection[current_run][self._reg_offset]
                    ):
                        l.debug(
                            "Overwriting %s with %s",
                            state_.registers.load(self._reg_offset),
                            self._info_collection[current_run][self._reg_offset],
                        )
                        state_.registers.store(self._reg_offset, self._info_collection[current_run][self._reg_offset])

        l.debug("Start back traversal from %s", current_block)

        # Create a partial CFG first
        temp_cfg = networkx.DiGraph(self.graph)
        # Reverse it
        temp_cfg.reverse(copy=False)

        path_length = 0
        concrete_exits = []
        if cfg_node not in temp_cfg.nodes():
            # TODO: Figure out why this is happening
            return concrete_exits

        keep_running = True
        while not concrete_exits and path_length < 5 and keep_running:
            path_length += 1
            queue = [cfg_node]
            avoid = set()
            for _ in range(path_length):
                new_queue = []
                for n in queue:
                    successors = list(temp_cfg.successors(n))
                    for suc in successors:
                        jk = temp_cfg.get_edge_data(n, suc)["jumpkind"]
                        if jk != "Ijk_Ret":
                            # We don't want to trace into libraries
                            predecessors = list(temp_cfg.predecessors(suc))
                            avoid |= {p.addr for p in predecessors if p is not n}
                            new_queue.append(suc)
                queue = new_queue

            if path_length <= 1:
                continue

            for n in queue:
                # Start symbolic exploration from each block
                state = self.project.factory.blank_state(
                    addr=n.addr,
                    mode="symbolic",
                    add_options={
                        o.DO_RET_EMULATION,
                        o.CONSERVATIVE_READ_STRATEGY,
                    }
                    | o.resilience,
                )
                # Avoid concretization of any symbolic read address that is over a certain limit
                # TODO: test case is needed for this option

                # Set initial values of persistent regs
                if n.addr in block_artifacts:
                    for reg in state.arch.persistent_regs:
                        state.registers.store(reg, block_artifacts[n.addr][reg])
                for reg in state.arch.persistent_regs:
                    reg_protector = RegisterProtector(reg, block_artifacts)
                    state.inspect.add_breakpoint(
                        "reg_write",
                        BP(
                            BP_AFTER,
                            reg_write_offset=state.arch.registers[reg][0],
                            action=reg_protector.write_persistent_register,
                        ),
                    )
                simgr = self.project.factory.simulation_manager(state)
                simgr.use_technique(LoopSeer(bound=10))
                simgr.use_technique(Explorer(find=current_block.addr, avoid=avoid))
                simgr.use_technique(LengthLimiter(path_length))
                simgr.run()

                if simgr.found:
                    simgr = self.project.factory.simulation_manager(simgr.one_found, save_unsat=True)
                    simgr.step()
                    if simgr.active or simgr.unsat:
                        keep_running = False
                        concrete_exits.extend(simgr.active)
                        concrete_exits.extend(simgr.unsat)
                if keep_running:
                    l.debug("Step back for one more run...")

        # Make sure these successors are actually concrete
        # We just use the ip, persistent registers, and jumpkind to initialize the original unsat state
        # TODO: It works for jumptables, but not for calls. We should also handle changes in sp
        new_concrete_successors = []
        for c in concrete_exits:
            unsat_state = current_block.unsat_successors[0].copy()
            unsat_state.history.jumpkind = c.history.jumpkind
            for reg in unsat_state.arch.persistent_regs + ["ip"]:
                unsat_state.registers.store(reg, c.registers.load(reg))
            new_concrete_successors.append(unsat_state)

        return new_concrete_successors

    def _get_symbolic_function_initial_state(self, function_addr, fastpath_mode_state=None):
        """
        Symbolically execute the first basic block of the specified function,
        then returns it. We prepares the state using the already existing
        state in fastpath mode (if avaiable).
        :param function_addr: The function address
        :return: A symbolic state if succeeded, None otherwise
        """
        if function_addr is None:
            return None

        if function_addr in self._symbolic_function_initial_state:
            return self._symbolic_function_initial_state[function_addr]

        if fastpath_mode_state is not None:
            fastpath_state = fastpath_mode_state
        else:
            if function_addr in self._function_input_states:
                fastpath_state = self._function_input_states[function_addr]
            else:
                raise AngrCFGError("The impossible happened. Please report to Fish.")

        symbolic_initial_state = self.project.factory.entry_state(mode="symbolic")
        if fastpath_state is not None:
            symbolic_initial_state = self.project.simos.prepare_call_state(
                fastpath_state, initial_state=symbolic_initial_state
            )

        # Find number of instructions of start block
        func = self.project.kb.functions.get(function_addr)
        start_block = func._get_block(function_addr)
        num_instr = start_block.instructions - 1

        symbolic_initial_state.ip = function_addr
        path = self.project.factory.path(symbolic_initial_state)
        try:
            sim_successors = self.project.factory.successors(path.state, num_inst=num_instr)
        except (SimError, AngrError):
            return None

        # We execute all but the last instruction in this basic block, so we have a cleaner
        # state
        # Start execution!
        exits = sim_successors.flat_successors + sim_successors.unsat_successors

        if exits:
            final_st = None
            for ex in exits:
                if ex.satisfiable():
                    final_st = ex
                    break
        else:
            final_st = None

        self._symbolic_function_initial_state[function_addr] = final_st

        return final_st

    # Private methods - function hints

    def _search_for_function_hints(self, successor_state):
        """
        Scan for constants that might be used as exit targets later, and add them into pending_exits.

        :param SimState successor_state: A successing state.
        :return:                                 A list of discovered code addresses.
        :rtype:                                  list
        """

        function_hints = []

        for action in successor_state.history.recent_actions:
            if action.type == "reg" and action.offset == self.project.arch.ip_offset:
                # Skip all accesses to IP registers
                continue
            if action.type == "exit":
                # only consider read/write actions
                continue

            # Enumerate actions
            if isinstance(action, SimActionData):
                data = action.data
                if data is not None:
                    # TODO: Check if there is a proper way to tell whether this const falls in the range of code
                    # TODO: segments
                    # Now let's live with this big hack...
                    try:
                        const = successor_state.solver.eval_one(data.ast)
                    except Exception:  # pylint:disable=broad-exception-caught
                        continue

                    if self._is_address_executable(const):
                        if self._pending_function_hints is not None and const in self._pending_function_hints:
                            continue

                        # target = const
                        # tpl = (None, None, target)
                        # st = self.project._simos.prepare_call_state(self.project.initial_state(mode='fastpath'),
                        #                                           initial_state=saved_state)
                        # st = self.project.initial_state(mode='fastpath')
                        # exits[tpl] = (st, None, None)

                        function_hints.append(const)

        l.debug(
            "Got %d possible exits, including: %s", len(function_hints), ", ".join(["0x%x" % f for f in function_hints])
        )

        return function_hints

    # Private methods - creation of stuff (SimSuccessors, CFGNode, call-stack, etc.)

    def _get_simsuccessors(self, addr, job, current_function_addr=None):
        """
        Create the SimSuccessors instance for a block.

        :param int addr:                  Address of the block.
        :param CFGJob job:                The CFG job instance with an input state inside.
        :param int current_function_addr: Address of the current function.
        :return:                          A SimSuccessors instance
        :rtype:                           SimSuccessors
        """

        exception_info = None
        state = job.state
        saved_state = job.state  # We don't have to make a copy here

        # respect the basic block size from base graph
        block_size = None
        if self._base_graph is not None:
            for n in self._base_graph.nodes():
                if n.addr == addr:
                    block_size = n.size
                    break

        try:
            sim_successors = None

            if not self._keep_state:
                if self.project.is_hooked(addr):
                    old_proc = self.project._sim_procedures[addr]
                    is_continuation = old_proc.is_continuation
                elif self.project.simos.is_syscall_addr(addr):
                    old_proc = self.project.simos.syscall_from_addr(addr)
                    is_continuation = False  # syscalls don't support continuation
                else:
                    old_proc = None
                    is_continuation = None

                if old_proc is not None and not is_continuation and not old_proc.ADDS_EXITS and not old_proc.NO_RET:
                    # DON'T CREATE USELESS SIMPROCEDURES if we don't care about the accuracy of states
                    # When generating CFG, a SimProcedure will not be created as it is but be created as a
                    # ReturnUnconstrained stub if it satisfies the following conditions:
                    # - It doesn't add any new exits.
                    # - It returns as normal.
                    # In this way, we can speed up the CFG generation by quite a lot as we avoid simulating
                    # those functions like read() and puts(), which has no impact on the overall control flow at all.
                    #
                    # Special notes about SimProcedure continuation: Any SimProcedure instance that is a continuation
                    # will add new exits, otherwise the original SimProcedure wouldn't have been executed anyway. Hence
                    # it's reasonable for us to always simulate a SimProcedure with continuation.

                    old_name = None

                    if old_proc.is_syscall:
                        new_stub = SIM_PROCEDURES["stubs"]["syscall"]
                        ret_to = state.regs.ip_at_syscall
                    else:
                        # normal SimProcedures
                        new_stub = SIM_PROCEDURES["stubs"]["ReturnUnconstrained"]
                        ret_to = None

                    old_name = old_proc.display_name

                    # instantiate the stub
                    new_stub_inst = new_stub(display_name=old_name)

                    sim_successors = self.project.factory.procedure_engine.process(
                        state,
                        procedure=new_stub_inst,
                        force_addr=addr,
                        ret_to=ret_to,
                    )

            if sim_successors is None:
                jumpkind = state.history.jumpkind
                jumpkind = "Ijk_Boring" if jumpkind is None else jumpkind
                sim_successors = self.project.factory.successors(
                    state, jumpkind=jumpkind, size=block_size, opt_level=self._iropt_level
                )

        except (SimFastPathError, SimSolverModeError) as ex:
            if saved_state.mode == "fastpath":
                # Got a SimFastPathError or SimSolverModeError in FastPath mode.
                # We wanna switch to symbolic mode for current IRSB.
                l.debug("Switch to symbolic mode for address %#x", addr)
                # Make a copy of the current 'fastpath' state

                l.debug("Symbolic jumps at basic block %#x.", addr)

                new_state = None
                if addr != current_function_addr:
                    new_state = self._get_symbolic_function_initial_state(current_function_addr)

                if new_state is None:
                    new_state = state.copy()
                    new_state.set_mode("symbolic")
                new_state.options.add(o.DO_RET_EMULATION)
                # Remove bad constraints
                # FIXME: This is so hackish...
                new_state.solver._solver.constraints = [
                    c for c in new_state.solver.constraints if c.op != "BoolV" or c.args[0] is not False
                ]
                new_state.solver._solver._result = None
                # Swap them
                saved_state, job.state = job.state, new_state
                sim_successors, exception_info, _ = self._get_simsuccessors(addr, job)

            else:
                exception_info = sys.exc_info()
                # Got a SimSolverModeError in symbolic mode. We are screwed.
                # Skip this IRSB
                l.debug("Caught a SimIRSBError %s. Don't panic, this is usually expected.", ex)
                inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
                sim_successors = ProcedureEngine().process(state, procedure=inst)

        except SimIRSBError:
            exception_info = sys.exc_info()
            # It's a tragedy that we came across some instructions that VEX
            # does not support. I'll create a terminating stub there
            l.debug("Caught a SimIRSBError during CFG recovery. Creating a PathTerminator.", exc_info=True)
            inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
            sim_successors = ProcedureEngine().process(state, procedure=inst)

        except claripy.ClaripyError:
            exception_info = sys.exc_info()
            l.debug("Caught a ClaripyError during CFG recovery. Don't panic, this is usually expected.", exc_info=True)
            # Generate a PathTerminator to terminate the current path
            inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
            sim_successors = ProcedureEngine().process(state, procedure=inst)

        except SimError:
            exception_info = sys.exc_info()
            l.debug("Caught a SimError during CFG recovery. Don't panic, this is usually expected.", exc_info=True)
            # Generate a PathTerminator to terminate the current path
            inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
            sim_successors = ProcedureEngine().process(state, procedure=inst)

        except AngrExitError:
            exception_info = sys.exc_info()
            l.debug("Caught a AngrExitError during CFG recovery. Don't panic, this is usually expected.", exc_info=True)
            # Generate a PathTerminator to terminate the current path
            inst = SIM_PROCEDURES["stubs"]["PathTerminator"]()
            sim_successors = ProcedureEngine().process(state, procedure=inst)

        except AngrError:
            exception_info = sys.exc_info()
            section = self.project.loader.main_object.find_section_containing(addr)
            if section is None:
                sec_name = "No section"
            else:
                sec_name = section.name
            # AngrError shouldn't really happen though
            l.debug("Caught an AngrError during CFG recovery at %#x (%s)", addr, sec_name, exc_info=True)
            # We might be on a wrong branch, and is likely to encounter the
            # "No bytes in memory xxx" exception
            # Just ignore it
            sim_successors = None

        return sim_successors, exception_info, saved_state

    def _create_new_call_stack(self, addr, all_jobs, job, exit_target, jumpkind):
        """
        Creates a new call stack, and according to the jumpkind performs appropriate actions.

        :param int addr:                          Address to create at.
        :param Simsuccessors all_jobs:            Jobs to get stack pointer from or return address.
        :param CFGJob job:                        CFGJob to copy current call stack from.
        :param int exit_target:                   Address of exit target.
        :param str jumpkind:                      The type of jump performed.
        :returns:                                 New call stack for target block.
        :rtype:                                   CallStack
        """

        if self._is_call_jumpkind(jumpkind):
            new_call_stack = job.call_stack_copy()
            # Notice that in ARM, there are some freaking instructions
            # like
            # BLEQ <address>
            # It should give us three exits: Ijk_Call, Ijk_Boring, and
            # Ijk_Ret. The last exit is simulated.
            # Notice: We assume the last exit is the simulated one
            if len(all_jobs) > 1 and all_jobs[-1].history.jumpkind == "Ijk_FakeRet":
                se = all_jobs[-1].solver
                retn_target_addr = se.eval_one(all_jobs[-1].ip, default=0)
                sp = se.eval_one(all_jobs[-1].regs.sp, default=0)

                new_call_stack = new_call_stack.call(addr, exit_target, retn_target=retn_target_addr, stack_pointer=sp)

            elif jumpkind.startswith("Ijk_Sys") and len(all_jobs) == 1:
                # This is a syscall. It returns to the same address as itself (with a different jumpkind)
                retn_target_addr = exit_target
                se = all_jobs[0].solver
                sp = se.eval_one(all_jobs[0].regs.sp, default=0)
                new_call_stack = new_call_stack.call(addr, exit_target, retn_target=retn_target_addr, stack_pointer=sp)

            else:
                # We don't have a fake return exit available, which means
                # this call doesn't return.
                new_call_stack = CallStack()
                se = all_jobs[-1].solver
                sp = se.eval_one(all_jobs[-1].regs.sp, default=0)

                new_call_stack = new_call_stack.call(addr, exit_target, retn_target=None, stack_pointer=sp)

        elif jumpkind == "Ijk_Ret":
            # Normal return
            new_call_stack = job.call_stack_copy()
            try:
                new_call_stack = new_call_stack.ret(exit_target)
            except SimEmptyCallStackError:
                pass

            se = all_jobs[-1].solver
            sp = se.eval_one(all_jobs[-1].regs.sp, default=0)
            old_sp = job.current_stack_pointer

            # Calculate the delta of stack pointer
            if sp is not None and old_sp is not None:
                delta = sp - old_sp
                func_addr = job.func_addr

                if self.kb.functions.function(func_addr) is None:
                    # Create the function if it doesn't exist
                    # FIXME: But hell, why doesn't it exist in the first place?
                    l.error(
                        "Function 0x%x doesn't exist in function manager although it should be there."
                        "Look into this issue later.",
                        func_addr,
                    )
                    self.kb.functions.function(func_addr, create=True)

                # Set sp_delta of the function
                self.kb.functions.function(func_addr, create=True).sp_delta = delta

        elif jumpkind == "Ijk_FakeRet":
            # The fake return...
            new_call_stack = job.call_stack

        else:
            # although the jumpkind is not Ijk_Call, it may still jump to a new function... let's see
            if self.project.is_hooked(exit_target):
                hooker = self.project.hooked_by(exit_target)
                if hooker is not procedures.stubs.UserHook.UserHook:
                    # if it's not a UserHook, it must be a function
                    # Update the function address of the most recent call stack frame
                    new_call_stack = job.call_stack_copy()
                    new_call_stack.current_function_address = exit_target

                else:
                    # TODO: We need a way to mark if a user hook is a function or not
                    # TODO: We can add a map in Project to store this information
                    # For now we are just assuming they are not functions, which is mostly the case
                    new_call_stack = job.call_stack

            else:
                # Normal control flow transition
                new_call_stack = job.call_stack

        return new_call_stack

    def _create_cfgnode(self, sim_successors, call_stack, func_addr, block_id=None, depth=None, exception_info=None):
        """
        Create a context-sensitive CFGNode instance for a specific block.

        :param SimSuccessors sim_successors:         The SimSuccessors object.
        :param CallStack call_stack_suffix:          The call stack.
        :param int func_addr:                        Address of the current function.
        :param BlockID block_id:                     The block ID of this CFGNode.
        :param int or None depth:                    Depth of this CFGNode.
        :return:                                     A CFGNode instance.
        :rtype:                                      CFGNode
        """

        sa = sim_successors.artifacts  # shorthand

        # Determine if this is a SimProcedure, and further, if this is a syscall
        syscall = None
        is_syscall = False
        if sim_successors.sort == "SimProcedure":
            is_simprocedure = True
            if sa["is_syscall"] is True:
                is_syscall = True
                syscall = sim_successors.artifacts["procedure"]
        else:
            is_simprocedure = False

        if is_simprocedure:
            simproc_name = sa["name"].split(".")[-1]
            if simproc_name == "ReturnUnconstrained" and "resolves" in sa and sa["resolves"] is not None:
                simproc_name = sa["resolves"]

            no_ret = False
            if syscall is not None and sa["no_ret"]:
                no_ret = True

            cfg_node = CFGENode(
                sim_successors.addr,
                None,
                self.model,
                callstack_key=call_stack.stack_suffix(self.context_sensitivity_level),
                input_state=None,
                simprocedure_name=simproc_name,
                syscall_name=syscall,
                no_ret=no_ret,
                is_syscall=is_syscall,
                function_address=sim_successors.addr,
                block_id=block_id,
                depth=depth,
                creation_failure_info=exception_info,
                thumb=(isinstance(self.project.arch, ArchARM) and sim_successors.addr & 1),
            )

        else:
            cfg_node = CFGENode(
                sim_successors.addr,
                sa["irsb_size"],
                self.model,
                callstack_key=call_stack.stack_suffix(self.context_sensitivity_level),
                input_state=None,
                is_syscall=is_syscall,
                function_address=func_addr,
                block_id=block_id,
                depth=depth,
                irsb=sim_successors.artifacts["irsb"],
                creation_failure_info=exception_info,
                thumb=(isinstance(self.project.arch, ArchARM) and sim_successors.addr & 1),
            )

        return cfg_node

    # Private methods - loops and graph normalization

    def _detect_loops(self, loop_callback=None):
        """
        Loop detection.

        :param func loop_callback: A callback function for each detected loop backedge.
        :return: None
        """

        loop_finder = self.project.analyses[LoopFinder].prep(kb=self.kb, fail_fast=self._fail_fast)(normalize=False)

        if loop_callback is not None:
            graph_copy = networkx.DiGraph(self._graph)

            loop: angr.analyses.loopfinder.Loop
            for loop in loop_finder.loops:
                loop_callback(graph_copy, loop)

            self.model.graph = graph_copy

        # Update loop backedges and graph
        self._loop_back_edges = list(itertools.chain.from_iterable(loop.continue_edges for loop in loop_finder.loops))

    # Private methods - function/procedure/subroutine analysis
    # Including calling convention, function arguments, etc.

    def _refine_function_arguments(self, func, callsites):
        """

        :param func:
        :param callsites:
        :return:
        """

        for i, c in enumerate(callsites):
            # Execute one block ahead of the callsite, and execute one basic block after the callsite
            # In this process, the following tasks are performed:
            # - Record registers/stack variables that are modified
            # - Record the change of the stack pointer
            # - Check if the return value is used immediately
            # We assume that the stack is balanced before and after the call (you can have caller clean-up of course).
            # Any abnormal behaviors will be logged.
            # Hopefully this approach will allow us to have a better understanding of parameters of those function
            # stubs and function proxies.

            if c.simprocedure_name is not None:
                # Skip all SimProcedures
                continue

            l.debug("Refining %s at 0x%x (%d/%d).", repr(func), c.addr, i, len(callsites))

            # Get a basic block ahead of the callsite
            blocks_ahead = [c]

            # the block after
            blocks_after = []
            successors = self.get_successors_and_jumpkind(c, excluding_fakeret=False)
            for s, jk in successors:
                if jk == "Ijk_FakeRet":
                    blocks_after = [s]
                    break

            regs_overwritten = set()
            stack_overwritten = set()
            regs_read = set()
            regs_written = set()

            try:
                # Execute the predecessor
                path = self.project.factory.path(
                    self.project.factory.blank_state(mode="fastpath", addr=blocks_ahead[0].addr)
                )
                path.step()
                all_successors = path.next_run.successors + path.next_run.unsat_successors
                if not all_successors:
                    continue

                suc = all_successors[0]
                se = suc.solver
                # Examine the path log
                actions = suc.history.recent_actions
                sp = se.eval_one(suc.regs.sp, default=0) + self.project.arch.call_sp_fix
                for ac in actions:
                    if ac.type == "reg" and ac.action == "write":
                        regs_overwritten.add(ac.offset)
                    elif ac.type == "mem" and ac.action == "write":
                        addr = se.eval_one(ac.addr.ast, default=0)
                        if (self.project.arch.call_pushes_ret and addr >= sp + self.project.arch.bytes) or (
                            not self.project.arch.call_pushes_ret and addr >= sp
                        ):
                            offset = addr - sp
                            stack_overwritten.add(offset)

                func.prepared_registers.add(tuple(regs_overwritten))
                func.prepared_stack_variables.add(tuple(stack_overwritten))

            except (SimError, AngrError):
                pass

            try:
                if blocks_after:
                    path = self.project.factory.path(
                        self.project.factory.blank_state(mode="fastpath", addr=blocks_after[0].addr)
                    )
                    path.step()
                    all_successors = path.next_run.successors + path.next_run.unsat_successors
                    if not all_successors:
                        continue

                    suc = all_successors[0]
                    actions = suc.history.recent_actions
                    for ac in actions:
                        if ac.type == "reg" and ac.action == "read" and ac.offset not in regs_written:
                            regs_read.add(ac.offset)
                        elif ac.type == "reg" and ac.action == "write":
                            regs_written.add(ac.offset)

                    # Filter registers, remove unnecessary registers from the set
                    # regs_overwritten = self.project.arch.argument_registers.intersection(regs_overwritten)
                    regs_read = self.project.arch.argument_registers.intersection(regs_read)

                    func.registers_read_afterwards.add(tuple(regs_read))

            except (SimError, AngrError):
                pass

    # Private methods - dominators and post-dominators

    def _immediate_dominators(self, node, target_graph=None, reverse_graph=False):
        """
        Get all immediate dominators of sub graph from given node upwards.

        :param str node: id of the node to navigate forwards from.
        :param networkx.classes.digraph.DiGraph target_graph: graph to analyse, default is self.graph.
        :param bool reverse_graph: Whether the target graph should be reversed before analysation.

        :return: each node of graph as index values, with element as respective node's immediate dominator.
        :rtype: dict
        """
        if target_graph is None:
            target_graph = self.graph

        if node not in target_graph:
            raise AngrCFGError("Target node %s is not in graph." % node)

        graph = networkx.DiGraph(target_graph)
        if reverse_graph:
            # Reverse the graph without deepcopy
            for n in target_graph.nodes():
                graph.add_node(n)
            for src, dst in target_graph.edges():
                graph.add_edge(dst, src)

        idom = {node: node}

        order = list(networkx.dfs_postorder_nodes(graph, node))
        dfn = {u: i for i, u in enumerate(order)}
        order.pop()
        order.reverse()

        def intersect(u_, v_):
            """
            Finds the highest (in postorder valuing) point of intersection above two node arguments.

            :param str u_: nx node id.
            :param str v_: nx node id.
            :return: intersection of paths.
            :rtype: str
            """
            while u_ != v_:
                while dfn[u_] < dfn[v_]:
                    u_ = idom[u_]
                while dfn[u_] > dfn[v_]:
                    v_ = idom[v_]
            return u_

        changed = True
        while changed:
            changed = False
            for u in order:
                new_idom = reduce(intersect, (v for v in graph.pred[u] if v in idom))
                if u not in idom or idom[u] != new_idom:
                    idom[u] = new_idom
                    changed = True

        return idom

    #
    # Static private utility methods
    #

    @staticmethod
    def _is_indirect_jump(_, sim_successors):
        """
        Determine if this SimIRSB has an indirect jump as its exit
        """

        if sim_successors.artifacts["irsb_direct_next"]:
            # It's a direct jump
            return False

        default_jumpkind = sim_successors.artifacts["irsb_default_jumpkind"]
        if default_jumpkind not in ("Ijk_Call", "Ijk_Boring", "Ijk_InvalICache"):
            # It's something else, like a ret of a syscall... we don't care about it
            return False

        return True

    @staticmethod
    def _generate_block_id(call_stack_suffix, block_addr, is_syscall):
        if not is_syscall:
            return BlockID.new(block_addr, call_stack_suffix, "normal")
        return BlockID.new(block_addr, call_stack_suffix, "syscall")

    @staticmethod
    def _block_id_repr(block_id):
        return repr(block_id)

    @staticmethod
    def _block_id_callstack_key(block_id):
        return block_id.callsite_tuples

    @staticmethod
    def _block_id_addr(block_id):
        return block_id.addr

    @staticmethod
    def _block_id_current_func_addr(block_id):
        """
        If we don't have any information about the caller, we have no way to get the address of the current function.

        :param BlockID block_id: The block ID.
        :return:                 The function address if there is one, or None if it's not possible to get.
        :rtype:                  int or None
        """

        if block_id.callsite_tuples:
            return block_id.callsite_tuples[-1]
        return None

    #
    # Other private utility methods
    #

    @staticmethod
    def _is_call_jumpkind(jumpkind):
        if jumpkind == "Ijk_Call" or jumpkind.startswith("Ijk_Sys_"):
            return True
        return False

    def _push_unresolvable_run(self, block_address):
        """
        Adds this block to the list of unresolvable runs.

        :param dict block_address: container of IRSB data from run.
        """
        self._unresolvable_runs.add(block_address)

    def _is_address_executable(self, address):
        """
        Check if the specific address is in one of the executable ranges.

        :param int address: The address
        :return: True if it's in an executable range, False otherwise
        """

        for r in self._executable_address_ranges:
            if r[0] <= address < r[1]:
                return True
        return False

    def _update_thumb_addrs(self, simsuccessors, state):
        """

        :return:
        """

        # For ARM THUMB mode
        if simsuccessors.sort == "IRSB" and state.thumb:
            insn_addrs = simsuccessors.artifacts["insn_addrs"]
            self._thumb_addrs.update(insn_addrs)
            self._thumb_addrs.update(map(lambda x: x + 1, insn_addrs))  # pylint:disable=bad-builtin

    def _get_callsites(self, function_address):
        """
        Get where a specific function is called.
        :param function_address:    Address of the target function
        :return:                    A list of CFGNodes whose exits include a call/jump to the given function
        """

        all_predecessors = []

        nodes = self.get_all_nodes(function_address)
        for n in nodes:
            predecessors = list(self.get_predecessors(n))
            all_predecessors.extend(predecessors)

        return all_predecessors

    def _get_nx_paths(self, begin, end):
        """
        Get the possible (networkx) simple paths between two nodes or addresses
        corresponding to nodes.
        Input: addresses or node instances
        Return: a list of lists of nodes representing paths.
        """
        if isinstance(begin, int) and isinstance(end, int):
            n_begin = self.get_any_node(begin)
            n_end = self.get_any_node(end)

        elif isinstance(begin, CFGENode) and isinstance(end, CFGENode):
            n_begin = begin
            n_end = end
        else:
            raise AngrCFGError("from and to should be of the same type")

        self.remove_fakerets()
        return networkx.all_shortest_paths(self.graph, n_begin, n_end)

    def _quasi_topological_sort(self):
        """
        Perform a quasi-topological sort on an already constructed CFG graph (a networkx DiGraph)

        :return: None
        """

        # Clear the existing sorting result
        self._quasi_topological_order = {}

        ctr = self._graph.number_of_nodes()

        for ep in self._entry_points:
            # FIXME: This is not always correct. We'd better store CFGNodes in self._entry_points
            ep_node = self.get_any_node(ep)

            if not ep_node:
                continue

            for n in networkx.dfs_postorder_nodes(self._graph, source=ep_node):
                if n not in self._quasi_topological_order:
                    self._quasi_topological_order[n] = ctr
                    ctr -= 1

    def _reset_state_mode(self, state, mode):
        """
        Reset the state mode to the given mode, and apply the custom state options specified with this analysis.

        :param state:    The state to work with.
        :param str mode: The state mode.
        :return:         None
        """

        state.set_mode(mode)
        state.options |= self._state_add_options
        state.options = state.options.difference(self._state_remove_options)


AnalysesHub.register_default("CFGEmulated", CFGEmulated)
