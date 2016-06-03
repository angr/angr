from collections import defaultdict
import logging

import itertools
import networkx

import pyvex
import simuvex
import claripy
from archinfo import ArchARM

from ..entry_wrapper import EntryWrapper
from ..analysis import Analysis, register_analysis
from ..errors import AngrCFGError, AngrError, AngrForwardAnalysisSkipEntry
from ..knowledge import FunctionManager
from ..path import make_path
from .cfg_node import CFGNode
from .cfg_base import CFGBase
from .forward_analysis import ForwardAnalysis

l = logging.getLogger(name="angr.analyses.cfg")


class PendingExit(object):
    def __init__(self, returning_source, state, src_simrun_key, src_exit_stmt_idx, bbl_stack, call_stack):
        """
        PendingExit is whatever will be put into our pending_exit list. A pending exit is an entry that created by the
        returning of a call or syscall. It is "pending" since we cannot immediately figure out whether this entry will
        be executed or not. If the corresponding call/syscall intentially doesn't return, then the pending exit will be
        removed. If the corresponding call/syscall returns, then the pending exit will be removed as well (since a real
        entry is created from the returning and will be analyzed later). If the corresponding call/syscall might
        return, but for some reason (for example, an unsupported instruction is met during the analysis) our analysis
        does not return properly, then the pending exit will be picked up and put into remaining_entries list.

        :param returning_source:    Address of the callee function. It might be None if address of the callee is not
                                    resolvable.
        :param state:               The state after returning from the callee function. Of course there is no way to get
                                    a precise state without emulating the execution of the callee, but at least we can
                                    properly adjust the stack and registers to imitate the real returned state.
        :param bbl_stack:           A basic block stack.
        :param call_stack:          A callstack.
        """

        self.returning_source = returning_source
        self.state = state
        self.src_simrun_key = src_simrun_key
        self.src_exit_stmt_idx = src_exit_stmt_idx
        self.bbl_stack = bbl_stack
        self.call_stack = call_stack

    def __repr__(self):
        return "<PendingExit to %s, from function %s>" % (self.state.ip, hex(
            self.returning_source) if self.returning_source is not None else 'Unknown')


class CFGAccurate(ForwardAnalysis, CFGBase):
    """
    This class represents a control-flow graph.
    """

    def __init__(self, context_sensitivity_level=1,
                 start=None,
                 avoid_runs=None,
                 enable_function_hints=False,
                 call_depth=None,
                 call_tracing_filter=None,
                 initial_state=None,
                 starts=None,
                 keep_state=False,
                 enable_advanced_backward_slicing=False,
                 enable_symbolic_back_traversal=False,
                 additional_edges=None,
                 no_construct=False
                 ):
        """
        All parameters are optional.

        :param context_sensitivity_level:           The level of context-sensitivity of this CFG (see documentation for further details)
                                                    It ranges from 0 to infinity. Default 1.
        :param avoid_runs:                          A list of runs to avoid.
        :param enable_function_hints:               Whether to use function hints (constants that might be used as exit targets) or not.
        :param call_depth:                          How deep in the call stack to trace.
        :param call_tracing_filter:                 Filter to apply on a given path and jumpkind to determine if it should be skipped when call_depth is reached
        :param initial_state:                       An initial state to use to begin analysis.
        :param starts:                              A list of addresses at which to begin analysis
        :param keep_state:                          Whether to keep the SimStates for each CFGNode.
        :param enable_advanced_backward_slicing:    Whether to enable an intensive technique for resolving direct jumps
        :param enable_symbolic_back_traversal:      Whether to enable an intensive technique for resolving indirect jumps
        :param additional_edges:                    A dict mapping addresses of basic blocks to addresses of
                                                    successors to manually include and analyze forward from.
        :param no_construct:                        Skip the construction procedure. Only used in unit-testing.
        """
        ForwardAnalysis.__init__(self)
        CFGBase.__init__(self, context_sensitivity_level)
        self._symbolic_function_initial_state = {}
        self._function_input_states = None
        self._loop_back_edges_set = set()

        self._unresolvable_runs = set()

        if start is not None:
            l.warning("`start` is deprecated. Please consider using `starts` instead in your code.")
            self._starts = (start,)
        else:
            if isinstance(starts, (list, set)):
                self._starts = tuple(starts)
            elif isinstance(starts, tuple) or starts is None:
                self._starts = starts
            else:
                raise AngrCFGError('Unsupported type of the `starts` argument.')

        self._avoid_runs = avoid_runs
        self._enable_function_hints = enable_function_hints
        self._call_depth = call_depth
        self._call_tracing_filter = call_tracing_filter
        self._initial_state = initial_state
        self._keep_state = keep_state
        self._advanced_backward_slicing = enable_advanced_backward_slicing
        self._enable_symbolic_back_traversal = enable_symbolic_back_traversal
        self._additional_edges = additional_edges if additional_edges else {}
        # Stores the index for each CFGNode in this CFG after a quasi-topological sort (currently a DFS)
        self._quasi_topological_order = {}
        # A copy of all entry points in this CFG. Integers
        self._entry_points = []

        self._nodes = {}
        self._nodes_by_addr = defaultdict(list)

        self._sanitize_parameters()

        self._executable_address_ranges = []
        self._executable_address_ranges = self._executable_memory_regions()

        if not no_construct:
            self._analyze()

    #
    # Public methods
    #

    def copy(self):
        """
        Make a copy of the CFG.

        :return: A copy of the CFG instance.
        :rtype: angr.analyses.CFG
        """
        new_cfg = CFGAccurate.__new__(CFGAccurate)
        new_cfg.named_errors = dict(self.named_errors)
        new_cfg.errors = list(self.errors)
        new_cfg._fail_fast = self._fail_fast
        new_cfg.project = self.project

        # Intelligently (or stupidly... you tell me) fill it up
        new_cfg._graph = networkx.DiGraph(self._graph)
        new_cfg._nodes = self._nodes.copy()
        new_cfg._nodes_by_addr = self._nodes_by_addr.copy()
        new_cfg._edge_map = self._edge_map.copy()
        new_cfg._loop_back_edges_set = self._loop_back_edges_set.copy()
        new_cfg._loop_back_edges = self._loop_back_edges[::]
        new_cfg._executable_address_ranges = self._executable_address_ranges[::]
        new_cfg._unresolvable_runs = self._unresolvable_runs.copy()
        new_cfg._overlapped_loop_headers = self._overlapped_loop_headers[::]
        new_cfg._thumb_addrs = self._thumb_addrs.copy()
        new_cfg._keep_state = self._keep_state
        new_cfg.project = self.project

        return new_cfg

    def get_lbe_exits(self):
        """
        -> Generator
        Returns a generator of exits of the loops
        based on the back egdes
        """
        for lirsb, _ in self._loop_back_edges:
            exits = lirsb.exits()
            yield exits

    def remove_cycles(self):
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

    def normalize(self):
        """
        Normalize the CFG, making sure there are no overlapping basic blocks.
        """

        # FIXME: Currently after normalization, CFG._nodes will not be updated, which will lead to some interesting
        # FIXME: bugs.
        # FIXME: Currently any information inside FunctionManager (including those functions) is not updated.

        graph = self.graph

        end_addresses = defaultdict(list)

        for n in graph.nodes():
            if n.is_simprocedure:
                continue
            end_addr = n.addr + n.size
            end_addresses[(end_addr, n.callstack_key)].append(n)

        while any([len(x) > 1 for x in end_addresses.itervalues()]):
            tpl_to_find = (None, None)
            for tpl, x in end_addresses.iteritems():
                if len(x) > 1:
                    tpl_to_find = tpl
                    break

            end_addr, callstack_key = tpl_to_find
            all_nodes = end_addresses[tpl_to_find]

            all_nodes = sorted(all_nodes, key=lambda node: node.size)
            smallest_node = all_nodes[0]
            other_nodes = all_nodes[1:]

            # Break other nodes
            for n in other_nodes:
                new_size = smallest_node.addr - n.addr
                if new_size == 0:
                    # This is the node that has the same size as the smallest one
                    continue

                new_end_addr = n.addr + new_size

                # Does it already exist?
                new_node = None
                tpl = (new_end_addr, n.callstack_key)
                if tpl in end_addresses:
                    nodes = [i for i in end_addresses[tpl] if i.addr == n.addr]
                    if len(nodes) > 0:
                        new_node = nodes[0]

                if new_node is None:
                    # Create a new one
                    new_node = CFGNode(n.addr, new_size, self, callstack_key=callstack_key, function_address=n.function_address)
                    # Copy instruction addresses
                    new_node.instruction_addrs = [ins_addr for ins_addr in n.instruction_addrs
                                                  if ins_addr < n.addr + new_size]
                    # Put the newnode into end_addresses
                    end_addresses[tpl].append(new_node)

                # Modify the CFG
                original_predecessors = list(graph.in_edges_iter([n], data=True))
                for p, _, _ in original_predecessors:
                    graph.remove_edge(p, n)
                graph.remove_node(n)

                for p, _, data in original_predecessors:
                    graph.add_edge(p, new_node, data)

                # We should find the correct successor
                new_successors = [i for i in all_nodes
                                  if i.addr == smallest_node.addr]
                if new_successors:
                    new_successor = new_successors[0]
                    graph.add_edge(new_node, new_successor, jumpkind='Ijk_Boring')
                else:
                    # We gotta create a new one
                    l.error('normalize(): Please report it to Fish.')

            end_addresses[tpl_to_find] = [smallest_node]

    def downsize(self):
        """
        Remove saved states from all CFGNodes to reduce memory usage.

        :return: None
        """

        for cfg_node in self._nodes.itervalues():
            cfg_node.downsize()

    def unroll_loops(self, max_loop_unrolling_times):
        if not isinstance(max_loop_unrolling_times, (int, long)) or \
                        max_loop_unrolling_times < 0:
            raise AngrCFGError('Max loop unrolling times must be set to an integer greater than or equal to 0 if ' +
                               'loop unrolling is enabled.')

        # Traverse the CFG and try to find the beginning of loops
        loop_backedges = []

        start = self._starts[0]
        if isinstance(start, tuple):
            start, _ = start  # pylint: disable=unpacking-non-sequence
        start_node = self.get_any_node(start)
        if start_node is None:
            raise AngrCFGError('Cannot find start node when trying to unroll loops. The CFG might be empty.')

        graph_copy = networkx.DiGraph(self.graph)

        while True:
            cycles_iter = networkx.simple_cycles(graph_copy)
            try:
                cycle = cycles_iter.next()
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
            end_nodes = [n for n in graph_copy.nodes_iter() if graph_copy.out_degree(n) == 0]
            new_end_node = "end_node"

            if len(end_nodes) == 0:
                # We gotta randomly break a loop
                cycles = sorted(networkx.simple_cycles(graph_copy), key=len)
                first_cycle = cycles[0]
                if len(first_cycle) == 1:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[0])
                else:
                    graph_copy.remove_edge(first_cycle[0], first_cycle[1])
                end_nodes = [n for n in graph_copy.nodes_iter() if graph_copy.out_degree(n) == 0]

            for en in end_nodes:
                graph_copy.add_edge(en, new_end_node)

            # postdoms = self.immediate_postdominators(new_end_node, target_graph=graph_copy)
            # reverse_postdoms = defaultdict(list)
            # for k, v in postdoms.iteritems():
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
                        new_dst not in graph_copy and
                        # If the new_dst is already in the graph, we don't want to keep unrolling
                        # the this loop anymore since it may *create* a new loop. Of course we
                        # will lose some edges in this way, but in general it is acceptable.
                        new_dst.looping_times <= max_loop_unrolling_times):
                    # Log all successors of the dst node
                    dst_successors = graph_copy.successors(dst)
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

        self._graph = graph_copy

    def immediate_dominators(self, start, target_graph=None):
        return self._immediate_dominators(start, target_graph=target_graph, reverse_graph=False)

    def immediate_postdominators(self, end, target_graph=None):
        return self._immediate_dominators(end, target_graph=target_graph, reverse_graph=True)

    def remove_fakerets(self):
        """
        Get rid of fake returns (i.e., Ijk_FakeRet edges) from this CFG

        :return: None
        """
        fakeret_edges = [ (src, dst) for src, dst, data in self.graph.edges_iter(data=True)
                         if data['jumpkind'] == 'Ijk_FakeRet' ]
        self.graph.remove_edges_from(fakeret_edges)

    def get_paths(self, begin, end, nb_max=0):
        """
        Get all the simple paths between @begin and @end.
        :param nb_max: Threshold for a maximum of paths to handle
        :return: a list of angr.Path instances.
        """
        paths = self._get_nx_paths(begin, end)
        a_paths = []
        if nb_max > 0:
            paths = itertools.islice(paths, 0, nb_max)
        for p in paths:
            runs = map(self.irsb_from_node, p)
            a_paths.append(make_path(self.project, runs))
        return a_paths

    def get_topological_order(self, cfg_node):
        """
        Get the topological order of a CFG Node.

        :param cfg_node: A CFGNode instance.
        :return: An integer representing its order, or None if the CFGNode does not exist in the graph.
        """

        if len(self._quasi_topological_order) == 0:
            self._quasi_topological_sort()

        return self._quasi_topological_order.get(cfg_node, None)

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
        subgraph_nodes = set([start_node])

        while stack:
            nw = stack.pop()
            n, call_depth = nw[0], nw[1]

            # Get successors
            edges = self.graph.out_edges(n, data=True)

            for _, dst, data in edges:
                if dst not in traversed_nodes:
                    # We see a new node!
                    traversed_nodes.add(dst)

                    if data['jumpkind'] == 'Ijk_Call':
                        if max_call_depth is None or (max_call_depth is not None and call_depth < max_call_depth):
                            subgraph_nodes.add(dst)
                            new_nw = (dst, call_depth + 1)
                            stack.append(new_nw)
                    elif data['jumpkind'] == 'Ijk_Ret':
                        if call_depth > 0:
                            subgraph_nodes.add(dst)
                            new_nw = (dst, call_depth - 1)
                            stack.append(new_nw)
                    else:
                        subgraph_nodes.add(dst)
                        new_nw = (dst, call_depth)
                        stack.append(new_nw)

        subgraph = networkx.subgraph(self.graph, subgraph_nodes)

        # Make it a CFG instance
        subcfg = self.copy()
        subcfg._graph = subgraph
        subcfg._starts = (start,)

        return subcfg

    @property
    def functions(self):
        return self.kb.functions

    #
    # Serialization
    #

    def __setstate__(self, s):
        self.project = s['project']
        self._graph = s['graph']
        self._loop_back_edges = s['_loop_back_edges']
        self._nodes = s['_nodes']
        self._nodes_by_addr = s['_nodes_by_addr']
        self._thumb_addrs = s['_thumb_addrs']
        self._unresolvable_runs = s['_unresolvable_runs']
        self._executable_address_ranges = s['_executable_address_ranges']

    def __getstate__(self):
        s = {
            'project': self.project,
            'graph': self._graph,
            '_loop_back_edges': self._loop_back_edges,
            '_nodes': self._nodes,
            '_nodes_by_addr': self._nodes_by_addr,
            '_thumb_addrs': self._thumb_addrs,
            '_unresolvable_runs': self._unresolvable_runs,
            '_executable_address_ranges': self._executable_address_ranges,
        }

        return s

    #
    # Properties
    #

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
            raise AngrCFGError('CFG hasn\'t been generated yet.')

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
            raise AngrCFGError('Additional edges can only be a list, set, tuple, or a dict.')

        # Check _advanced_backward_slicing
        if self._advanced_backward_slicing and self._enable_symbolic_back_traversal:
            raise AngrCFGError('Advanced backward slicing and symbolic back traversal cannot both be enabled.')

        if self._advanced_backward_slicing and not self._keep_state:
            raise AngrCFGError('Keep state must be enabled if advanced backward slicing is enabled.')

        # Sanitize avoid_runs
        self._avoid_runs = [ ] if self._avoid_runs is None else self._avoid_runs
        if not isinstance(self._avoid_runs, (list, set)):
            raise AngrCFGError('"avoid_runs" must either be None, or a list or a set.')

        # Sanitize starts
        # Convert self._starts to a list of SimState instances or tuples of (ip, jumpkind)
        if self._starts is None:
            self._starts = ((self.project.entry, None),)

        else:
            new_starts = [ ]
            for item in self._starts:
                if isinstance(item, tuple):
                    if len(item) != 2:
                        raise AngrCFGError('Unsupported item in "starts": %s' % str(item))

                    new_starts.append(item)
                elif isinstance(item, (int, long)):
                    new_starts.append((item, None))

                elif isinstance(item, simuvex.SimState):
                    new_starts.append(item)

            self._starts = new_starts

        if not self._starts:
            raise AngrCFGError("At least one start must be provided")

    # CFG construction
    # The main loop and sub-methods

    def _init_analysis(self):
        """
        Initialization work.

        :return: None
        """

        # First call _init_analysis() from base class
        ForwardAnalysis._init_analysis(self)

        self._initialize_cfg()

        # Save input states of functions. It will be discarded after the CFG is constructed
        self._function_input_states = {}
        self._loop_back_edges_set = set()
        self._loop_back_edges = []
        self._overlapped_loop_headers = []
        self._pending_function_hints = set()
        # A dict to log edges and the jumpkind between each basic block
        self._edge_map = defaultdict(list)

        # Traverse all the IRSBs, and put the corresponding CFGNode objects to a dict
        # CFGNodes dict indexed by SimRun key
        self._nodes = {}
        # CFGNodes dict indexed by addresses of each SimRun
        self._nodes_by_addr = defaultdict(list)

        # For each call, we are always getting two exits: an Ijk_Call that
        # stands for the real call exit, and an Ijk_Ret that is a simulated exit
        # for the retn address. There are certain cases that the control flow
        # never returns to the next instruction of a callsite due to
        # imprecision of the concrete execution. So we save those simulated
        # exits here to increase our code coverage. Of course the real retn from
        # that call always precedes those "fake" retns.
        # Tuple --> (Initial state, call_stack, bbl_stack)
        self._pending_entries = { }

        # Counting how many times a basic block is traced into
        self._traced_addrs = defaultdict(lambda: defaultdict(int))

        # A dict that collects essential parameters to properly reconstruct initial state for a SimRun
        self._simrun_info_collection = {}
        self._analyzed_addrs = set()
        self._non_returning_functions = set()

        # Fill up self._starts
        for item in self._starts:
            if isinstance(item, tuple):
                # (addr, jumpkind)
                ip = item[0]
                state = self._create_initial_state(item[0], item[1])

            else:
                # simuvex.SimState
                state = item
                ip = state.se.exactly_int(state.ip)

            self._symbolic_function_initial_state[ip] = state

            entry_path = self.project.factory.path(state)
            path_wrapper = EntryWrapper(entry_path, self._context_sensitivity_level, None, None)

            self._entries.append(path_wrapper)

    def _pre_analysis(self):
        """
        Executed prior to the analysis.
        - Clean up the knowledge base

        :return: None
        """

        self.kb.functions = FunctionManager(self.kb)

    def _intra_analysis(self):
        """
        During the analysis. We process function hints here.

        :return: None
        """

        # TODO: Why was the former two conditions there in the first place?
        # if remaining_entries and pending_entries and self._pending_function_hints:
        if self._pending_function_hints:
            self._process_hints(self._analyzed_addrs, self._pending_entries)

    def _entry_list_empty(self):
        """

        :return:
        """

        if len(self._pending_entries):
            # There are no more remaining entries, but only pending entries left. Each pending entry corresponds to
            # a previous entry that does not return properly.
            # Now it's a good time to analyze each function (that we have so far) and determine if it is a)
            # returning, b) not returning, or c) unknown. For those functions that are definitely not returning,
            # remove the corresponding pending exits from `pending_entries` array. Perform this procedure iteratively
            # until no new not-returning functions appear. Then we pick a pending exit based on the following
            # priorities:
            # - Entry pended by a returning function
            # - Entry pended by an unknown function

            while True:
                new_changes = self._analyze_function_features()
                if not new_changes['functions_do_not_return']:
                    break

            self._clean_pending_exits(self._pending_entries)

        while len(self._pending_entries) > 0:
            # We don't have any exits remaining. Let's pop out a pending exit
            pending_entry = self._get_pending_entry()
            if pending_entry is None:
                continue

            self._entries.append(pending_entry)
            break

    def _create_initial_state(self, ip, jumpkind):
        """
        Obtain a SimState object for a specific address

        Fastpath means the CFG generation will work in an IDA-like way, in which it will not try to execute every
        single statement in the emulator, but will just do the decoding job. This is much faster than the old way.

        :param int ip: The instruction pointer
        :param str jumpkind: The jumpkind upon executing the block
        :return: The newly-generated state
        :rtype: simuvex.SimState
        """

        jumpkind = "Ijk_Boring" if jumpkind is None else jumpkind

        if self._initial_state is None:
            state = self.project.factory.entry_state(addr=ip, mode="fastpath")
        else:
            # FIXME: self._initial_state is deprecated. This branch will be removed soon
            state = self._initial_state
            state.scratch.jumpkind = jumpkind
            state.set_mode('fastpath')
            state.ip = state.se.BVV(ip, self.project.arch.bits)

        if jumpkind is not None:
            state.scratch.jumpkind = jumpkind

        state_info = None
        # THIS IS A HACK FOR MIPS and ALSO PPC64
        if ip is not None and self.project.arch.name in ('MIPS32', 'MIPS64'):
            # We assume this is a function start
            state_info = {'t9': state.se.BVV(ip, self.project.arch.bits)}
        elif ip is not None and self.project.arch.name == 'PPC64':
            # Still assuming this is a function start
            state_info = {'r2': state.registers.load('r2')}
        state = self.project.arch.prepare_state(state, state_info)

        return state

    def _get_pending_entry(self):
        """
        Retrieve a pending entry from all pended ones.

        :return: An EntryWrapper instance or None
        """

        pending_exit_tuple = self._pending_entries.keys()[0]
        pending_exit = self._pending_entries.pop(pending_exit_tuple)
        pending_exit_state = pending_exit.state
        pending_exit_call_stack = pending_exit.call_stack
        pending_exit_bbl_stack = pending_exit.bbl_stack
        pending_entry_src_simrun_key = pending_exit.src_simrun_key
        pending_entry_src_exit_stmt_idx = pending_exit.src_exit_stmt_idx

        # Let's check whether this address has been traced before.
        if pending_exit_tuple in self._nodes:
            node = self._nodes[pending_exit_tuple]
            if node in self.graph:
                pending_exit_addr = self._simrun_key_addr(pending_exit_tuple)
                # That block has been traced before. Let's forget about it
                l.debug("Target 0x%08x has been traced before. " + "Trying the next one...", pending_exit_addr)

                # However, we should still create the FakeRet edge
                self._graph_add_edge(pending_entry_src_simrun_key, pending_exit_tuple, jumpkind="Ijk_FakeRet",
                                     exit_stmt_idx=pending_entry_src_exit_stmt_idx)

                return None

        pending_exit_state.scratch.jumpkind = 'Ijk_FakeRet'

        path = self.project.factory.path(pending_exit_state)
        entry = EntryWrapper(path,
                                    self._context_sensitivity_level,
                                    pending_entry_src_simrun_key,
                                    pending_entry_src_exit_stmt_idx,
                                    call_stack=pending_exit_call_stack,
                                    bbl_stack=pending_exit_bbl_stack
                                    )
        l.debug("Tracing a missing return exit %s", self._simrun_key_repr(pending_exit_tuple))

        return entry

    def _process_hints(self, analyzed_addrs, remaining_entries):
        """
        Process function hints in the binary.

        :return: None
        """

        # Function hints!
        # Now let's see how many new functions we can get here...
        while self._pending_function_hints:
            f = self._pending_function_hints.pop()
            if f not in analyzed_addrs:
                new_state = self.project.factory.entry_state('fastpath')
                new_state.ip = new_state.se.BVV(f, self.project.arch.bits)

                # TOOD: Specially for MIPS
                if new_state.arch.name in ('MIPS32', 'MIPS64'):
                    # Properly set t9
                    new_state.registers.store('t9', f)

                new_path = self.project.factory.path(new_state)
                new_path_wrapper = EntryWrapper(new_path,
                                                self._context_sensitivity_level
                                                )
                remaining_entries.append(new_path_wrapper)
                l.debug('Picking a function 0x%x from pending function hints.', f)
                self.kb.functions.function(new_path_wrapper.current_function_address, create=True)
                break

    def _post_analysis(self):
        """
        Post-CFG-construction

        :return: None
        """

        # Remove those edges that will never be taken!
        self._remove_non_return_edges()

        # Perform function calling convention analysis
        self._analyze_calling_conventions()

        # Normalize all loop backedges
        self._normalize_loop_backedges()

        # Discard intermediate state dicts
        delattr(self, "_function_input_states")

    # Entry handling

    def _pre_entry_handling(self, entry, _locals):
        """
        Before processing an entry.
        Right now each SimRun is traced at most once. If it is traced more than once, we will mark it as "should_skip"
        before tracing it.
        An AngrForwardAnalysisSkipEntry exception is raised in order to skip analyzing the entry.

        :param EntryWrapper entry: The entry object
        :param dict _locals: A bunch of local variables that will be kept around when handling this entry and its
                        corresponding successors.
        :return: None
        """

        # Extract initial info from entry_wrapper
        path = _locals['path'] = entry.path
        call_stack_suffix = _locals['call_stack_suffix'] = entry.call_stack_suffix()
        addr = _locals['addr'] = entry.path.addr
        func_addr = _locals['func_addr'] = entry.current_function_address
        _locals['current_stack_pointer'] = entry.current_stack_pointer
        _locals['accessed_registers_in_function'] = entry.current_function_accessed_registers
        jumpkind = _locals['jumpkind'] = 'Ijk_Boring' if entry.path.state.scratch.jumpkind is None else \
            entry.path.state.scratch.jumpkind
        _locals['current_function'] = self.kb.functions.function(_locals['func_addr'], create=True,
                                                                 syscall=jumpkind.startswith("Ijk_Sys"))
        src_simrun_key = entry.src_simrun_key
        src_exit_stmt_idx = entry.src_exit_stmt_idx

        # Log this address
        if l.level == logging.DEBUG:
            self._analyzed_addrs.add(addr)

        if addr == func_addr:
            # Store the input state of this function
            self._function_input_states[func_addr] = path.state

        # Generate a unique key for this SimRun
        simrun_key = self._generate_simrun_key(call_stack_suffix, addr, jumpkind.startswith('Ijk_Sys'))

        # Should we skip tracing this SimRun?
        should_skip = False
        if self._traced_addrs[call_stack_suffix][addr] > 1:
            should_skip = True
        elif (jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys')) and \
                (self._call_depth is not None and
                         len(entry.call_stack) > self._call_depth and
                     (
                            self._call_tracing_filter is None or
                            self._call_tracing_filter(path.state, jumpkind)
                     )
                 ):
            should_skip = True

        # Get a SimRun out of current SimExit
        simrun, error_occurred, _ = self._get_simrun(addr, path, current_function_addr=func_addr)
        if simrun is None or should_skip:
            # We cannot retrieve the SimRun, or we should skip the analysis of this node

            # But we create the edge anyway. If the simrun does not exist, it will be an edge from the previous node to
            # a PathTerminator
            self._graph_add_edge(src_simrun_key, simrun_key, jumpkind=jumpkind, exit_stmt_idx=src_exit_stmt_idx)
            self._update_function_transition_graph(src_simrun_key, simrun_key, jumpkind=jumpkind)

            # If this entry cancels another FakeRet entry, we should also create the FekeRet edge
            if entry.cancelled_pending_entry is not None:
                pending_entry = entry.cancelled_pending_entry
                self._graph_add_edge(pending_entry.src_simrun_key, simrun_key, jumpkind='Ijk_FakeRet',
                                     exit_stmt_idx=pending_entry.src_exit_stmt_idx
                                     )
                self._update_function_transition_graph(pending_entry.src_simrun_key, simrun_key, jumpkind='Ijk_FakeRet')

            # We are good. Raise the exception and leave
            raise AngrForwardAnalysisSkipEntry()

        self._update_thumb_addrs(simrun, path.state)

        # We store the function hints first. Function hints will be checked at the end of the analysis to avoid
        # any duplication with existing jumping targets
        if self._enable_function_hints:
            function_hints = self._search_for_function_hints(simrun)
            for f in function_hints:
                self._pending_function_hints.add(f)

        # Increment tracing count for this SimRun
        self._traced_addrs[call_stack_suffix][addr] += 1

        # Create the CFGNode object
        cfg_node = self._create_cfgnode(simrun, call_stack_suffix, func_addr)

        if self._keep_state:
            cfg_node.input_state = simrun.initial_state

        self._nodes[simrun_key] = cfg_node
        self._nodes_by_addr[cfg_node.addr].append((simrun_key, cfg_node))

        self._graph_add_edge(src_simrun_key, simrun_key, jumpkind=jumpkind, exit_stmt_idx=src_exit_stmt_idx)
        self._update_function_transition_graph(src_simrun_key, simrun_key, jumpkind=jumpkind)

        # See if this entry cancels another FakeRet
        if entry.cancelled_pending_entry is not None:
            pending_entry = entry.cancelled_pending_entry
            self._graph_add_edge(pending_entry.src_simrun_key, simrun_key, jumpkind='Ijk_FakeRet',
                                 exit_stmt_idx=pending_entry.src_exit_stmt_idx
                                 )
            self._update_function_transition_graph(pending_entry.src_simrun_key, simrun_key, jumpkind='Ijk_FakeRet')

        simrun_info = self.project.arch.gather_info_from_state(simrun.initial_state)
        self._simrun_info_collection[addr] = simrun_info

        _locals['simrun'] = simrun
        _locals['simrun_key'] = simrun_key
        _locals['cfg_node'] = cfg_node
        _locals['error_occurred'] = error_occurred

        # For debugging purposes!
        _locals['successor_status'] = {}

    def _get_successors(self, entry, _locals):
        """

        :param entry:
        :param _locals:
        :return:
        """

        simrun = _locals['simrun']
        addr = _locals['addr']
        cfg_node = _locals['cfg_node']
        func_addr = _locals['func_addr']
        current_function = _locals['current_function']
        error_occurred = _locals['error_occurred']
        simrun_key = _locals['simrun_key']
        current_stack_pointer = _locals['current_stack_pointer']
        accessed_registers_in_function = _locals['accessed_registers_in_function']

        # Get all successors of this SimRun
        successors = (simrun.flat_successors + simrun.unsat_successors) if addr not in self._avoid_runs else []

        # Post-process successors
        successors, extra_info = self._post_process_successors(simrun, successors)

        _locals['extra_info'] = extra_info

        if self._keep_state:
            cfg_node.final_states = successors[::]

        # Try to resolve indirect jumps
        successors = self._resolve_indirect_jumps(simrun, cfg_node, func_addr, successors, error_occurred,
                                                  self._simrun_info_collection
                                                  )

        # Ad additional edges supplied by the user
        successors = self._add_additional_edges(simrun, cfg_node, successors)

        if len(successors) == 0:
            # There is no way out :-(
            # Log it first
            self._push_unresolvable_run(addr)

            if isinstance(simrun,
                          simuvex.procedures.SimProcedures["stubs"]["PathTerminator"]):
                # If there is no valid exit in this branch and it's not
                # intentional (e.g. caused by a SimProcedure that does not
                # do_return) , we should make it return to its call-site. However,
                # we don't want to use its state anymore as it might be corrupted.
                # Just create an edge in the graph.
                retn_target = entry.call_stack.current_return_target
                if retn_target is not None:
                    new_call_stack = entry.call_stack_copy()
                    exit_target_tpl = self._generate_simrun_key(
                        new_call_stack.stack_suffix(self.context_sensitivity_level),
                        retn_target,
                        False
                    )  # You can never return to a syscall
                    self._graph_add_edge(simrun_key, exit_target_tpl, jumpkind='Ijk_Ret', exit_stmt_id='default')

            else:
                # Well, there is just no successors. What can you expect?
                pass

        #
        # Enough foreplay. Time to do real job!
        #

        # First, handle all actions
        if successors:
            self._handle_actions(successors[0], simrun, current_function, current_stack_pointer,
                                 accessed_registers_in_function)

        return successors

    def _post_entry_handling(self, entry, successors, _locals):
        """

        :param entry:
        :param successors:
        :param _locals:
        :return:
        """

        extra_info = _locals['extra_info']
        cfg_node = _locals['cfg_node']

        # Finally, post-process CFG Node and log the return target
        if extra_info['is_call_jump'] and extra_info['return_target'] is not None:
            cfg_node.return_target = extra_info['return_target']

        # Debugging output if needed
        if l.level == logging.DEBUG:
            # Only in DEBUG mode do we process and output all those shit
            self._post_handle_entry_debug(entry, successors, _locals)

    def _post_process_successors(self, simrun, successors):
        """

        :return: A list of successors
        :rtype: list
        """

        if simrun.initial_state.thumb and isinstance(simrun, simuvex.SimIRSB):
            pyvex.set_iropt_level(0) # FIXME: Should we recovery the iropt level late?
            it_counter = 0
            conc_temps = {}
            can_produce_exits = set()
            bb = self.project.factory.block(simrun.addr, thumb=True)

            for stmt in bb.vex.statements:
                if stmt.tag == 'Ist_IMark':
                    if it_counter > 0:
                        it_counter -= 1
                        can_produce_exits.add(stmt.addr)
                elif stmt.tag == 'Ist_WrTmp':
                    val = stmt.data
                    if val.tag == 'Iex_Const':
                        conc_temps[stmt.tmp] = val.con.val
                elif stmt.tag == 'Ist_Put':
                    if stmt.offset == self.project.arch.registers['itstate'][0]:
                        val = stmt.data
                        if val.tag == 'Iex_RdTmp':
                            if val.tmp in conc_temps:
                                # We found an IT instruction!!
                                # Determine how many instructions are conditional
                                it_counter = 0
                                itstate = conc_temps[val.tmp]
                                while itstate != 0:
                                    it_counter += 1
                                    itstate >>= 8

            if it_counter != 0:
                l.error('Basic block ends before calculated IT block (%#x)', simrun.addr)

            THUMB_BRANCH_INSTRUCTIONS = ('beq', 'bne', 'bcs', 'bhs', 'bcc', 'blo', 'bmi', 'bpl', 'bvs',
                                         'bvc', 'bhi', 'bls', 'bge', 'blt', 'bgt', 'ble', 'cbz', 'cbnz')
            for cs_insn in bb.capstone.insns:
                if cs_insn.mnemonic in THUMB_BRANCH_INSTRUCTIONS:
                    can_produce_exits.add(cs_insn.address)

            successors = filter(lambda state: state.scratch.ins_addr in can_produce_exits or
                                              state.scratch.stmt_idx == simrun.num_stmts,
                                    successors
                                )

        # If there is a call exit, we shouldn't put the default exit (which
        # is artificial) into the CFG. The exits will be Ijk_Call and
        # Ijk_FakeRet, and Ijk_Call always goes first
        extra_info = {'is_call_jump': False,
                      'call_target': None,
                      'return_target': None,
                      'last_call_exit_target': None,
                      'skip_fakeret': False,
                      }

        # Post-process jumpkind before touching all_successors
        for suc in successors:
            suc_jumpkind = suc.scratch.jumpkind
            if suc_jumpkind == "Ijk_Call" or suc_jumpkind.startswith('Ijk_Sys'):
                extra_info['is_call_jump'] = True

        if successors:
            # Special case: Add a fakeret successor for Ijk_Sys_*
            if successors[0].scratch.jumpkind.startswith('Ijk_Sys'):
                # This is a syscall!
                copied = successors[0].copy()
                copied.scratch.jumpkind = 'Ijk_FakeRet'
                successors.append(copied)

        return successors, extra_info

    def _post_handle_entry_debug(self, entry, successors, _locals):
        """

        :return:
        """

        simrun = _locals['simrun']
        call_stack_suffix = _locals['call_stack_suffix']
        extra_info = _locals['extra_info']
        successor_status = _locals['successor_status']

        function_name = self.project.loader.find_symbol_name(simrun.addr)
        module_name = self.project.loader.find_module_name(simrun.addr)

        l.debug("Basic block %s %s", simrun, "->".join([hex(i) for i in call_stack_suffix if i is not None]))
        l.debug("(Function %s of binary %s)", function_name, module_name)
        l.debug("|    Call jump: %s", extra_info['is_call_jump'])

        for suc in successors:
            jumpkind = suc.scratch.jumpkind
            if jumpkind == "Ijk_FakeRet":
                exit_type_str = "Simulated Ret"
            else:
                exit_type_str = "-"
            try:
                l.debug("|    target: %#x %s [%s] %s", suc.se.exactly_int(suc.ip), successor_status[suc],
                        exit_type_str, jumpkind)
            except (simuvex.SimValueError, simuvex.SimSolverModeError):
                l.debug("|    target cannot be concretized. %s [%s] %s", successor_status[suc], exit_type_str,
                        jumpkind)
        l.debug("%d exits remaining, %d exits pending.", len(self._entries), len(self._pending_entries))
        l.debug("%d unique basic blocks are analyzed so far.", len(self._analyzed_addrs))

    def _clean_pending_exits(self, pending_exits):
        """
        Remove those pending exits if:
        a) they are the return exits of non-returning SimProcedures
        b) they are the return exits of non-returning syscalls
        b) they are the return exits of non-returning functions

        :param pending_exits: A dict of all pending exits
        """

        pending_exits_to_remove = []

        for simrun_key, pe in pending_exits.iteritems():

            if pe.returning_source is None:
                # The original call failed. This pending exit must be followed.
                continue

            func = self.kb.functions.function(pe.returning_source)
            if func is None:
                # Why does it happen?
                l.warning("An expected function at %s is not found. Please report it to Fish.",
                          hex(pe.returning_source) if pe.returning_source is not None else 'None')
                continue

            if func.returning is False:
                # Oops, it's not returning
                # Remove this pending exit
                pending_exits_to_remove.append(simrun_key)

                # We want to mark that call as not returning in the current function
                current_function_addr = self._simrun_key_current_func_addr(simrun_key)
                if current_function_addr is not None:
                    current_function = self.kb.functions.function(current_function_addr)
                    call_site_addr = self._simrun_key_addr(pe.src_simrun_key)
                    current_function._call_sites[call_site_addr] = (func.addr, None)

        for simrun_key in pending_exits_to_remove:
            l.debug('Removing a pending exit to 0x%x since the target function 0x%x does not return',
                    self._simrun_key_addr(simrun_key),
                    pending_exits[simrun_key].returning_source,
                    )

            del pending_exits[simrun_key]

    # Entry successor handling

    def _pre_handle_successor_state(self, extra_info, jumpkind, target_addr):
        """

        :return: None
        """

        # Fill up extra_info
        if (extra_info['is_call_jump'] and
                (jumpkind == 'Ijk_Call' or jumpkind.startswith('Ijk_Sys'))):
            extra_info['call_target'] = target_addr

        if (extra_info['is_call_jump'] and
                    jumpkind == 'Ijk_FakeRet'):
            extra_info['return_target'] = target_addr

        if jumpkind == "Ijk_Call":
            extra_info['last_call_exit_target'] = target_addr

    def _handle_successor(self, entry, successor, successors, _locals):
        """
        Returns a new PathWrapper instance for further analysis, or None if there is no immediate state to perform the
        analysis on.
        """

        state = successor
        all_successor_states = successors
        entry_wrapper = entry

        simrun = _locals['simrun']
        simrun_key = _locals['simrun_key']
        addr = _locals['addr']
        func_addr = _locals['func_addr']
        call_stack_suffix = _locals['call_stack_suffix']
        extra_info = _locals['extra_info']
        # retn_target_sources, extra_info
        successor_status = _locals['successor_status']

        # The PathWrapper instance to return
        pw = None

        successor_status[state] = ""

        new_state = state.copy()
        suc_jumpkind = state.scratch.jumpkind
        suc_exit_stmt_idx = state.scratch.exit_stmt_idx

        if suc_jumpkind in {'Ijk_EmWarn', 'Ijk_NoDecode', 'Ijk_MapFail', 'Ijk_InvalICache', 'Ijk_NoRedir',
                            'Ijk_SigTRAP', 'Ijk_SigSEGV', 'Ijk_ClientReq'}:
            # Ignore SimExits that are of these jumpkinds
            successor_status[state] = "Skipped"
            return

        if suc_jumpkind == "Ijk_FakeRet" and extra_info['call_target'] is not None:
            # if the call points to a SimProcedure that doesn't return, we don't follow the fakeret anymore
            if self.project.is_hooked(extra_info['call_target']):
                sim_proc = self.project._sim_procedures[extra_info['call_target']][0]
                if sim_proc.NO_RET:
                    return

        # Get target address
        try:
            target_addr = state.se.exactly_n_int(state.ip, 1)[0]
        except (simuvex.SimValueError, simuvex.SimSolverModeError):
            # It cannot be concretized currently. Maybe we can handle it later, maybe it just cannot be concretized
            target_addr = None
            if suc_jumpkind == "Ijk_Ret":
                target_addr = entry_wrapper.call_stack.current_return_target
                if target_addr is not None:
                    new_state.ip = new_state.se.BVV(target_addr, new_state.arch.bits)

        if target_addr is None:
            # Unlucky...
            return

        if state.thumb:
            # Make sure addresses are always odd. It is important to encode this information in the address for the
            # time being.
            target_addr |= 1

        self._pre_handle_successor_state(extra_info, suc_jumpkind, target_addr)

        # Fix target_addr for syscalls
        if suc_jumpkind.startswith("Ijk_Sys"):
            _, target_addr, _, _ = self.project._simos.syscall_info(new_state)

        # Remove pending targets - type 2
        tpl = self._generate_simrun_key(call_stack_suffix, target_addr, suc_jumpkind.startswith('Ijk_Sys'))
        cancelled_pending_entry = None
        if suc_jumpkind == 'Ijk_Ret' and tpl in self._pending_entries:

            # The fake ret is confirmed (since we are returning from the function it calls). Create an edge for it in
            # the graph
            cancelled_pending_entry = self._pending_entries[tpl]
            l.debug("Removing pending exits (type 2) to %s", hex(target_addr))
            del self._pending_entries[tpl]

        if suc_jumpkind == "Ijk_FakeRet":
            if target_addr == extra_info['last_call_exit_target']:
                l.debug("... skipping a fake return exit that has the same target with its call exit.")
                successor_status[state] = "Skipped"
                return

            if extra_info['skip_fakeret']:
                l.debug('... skipping a fake return exit since the function it\'s calling doesn\'t return')
                successor_status[state] = "Skipped - non-returning function 0x%x" % extra_info['call_target']
                return

        # TODO: Make it optional
        if (suc_jumpkind == 'Ijk_Ret' and
                    self._call_depth is not None and
                    len(entry_wrapper.call_stack) <= 1
            ):
            # We cannot continue anymore since this is the end of the function where we started tracing
            l.debug('... reaching the end of the starting function, skip.')
            successor_status[state] = "Skipped - reaching the end of the starting function"
            return

        # Create the new call stack of target block
        new_call_stack = self._create_new_call_stack(addr, all_successor_states, entry_wrapper, target_addr,
                                                     suc_jumpkind)
        # Create the callstack suffix
        new_call_stack_suffix = new_call_stack.stack_suffix(self._context_sensitivity_level)
        # Tuple that will be used to index this exit
        new_tpl = self._generate_simrun_key(new_call_stack_suffix, target_addr, suc_jumpkind.startswith('Ijk_Sys'))

        if isinstance(simrun, simuvex.SimIRSB):
            self._detect_loop(simrun,
                              new_tpl,
                              simrun_key,
                              new_call_stack_suffix,
                              target_addr,
                              suc_jumpkind,
                              entry_wrapper,
                              func_addr)

        # Generate the new BBL stack of target block
        if suc_jumpkind == "Ijk_Call" or suc_jumpkind.startswith('Ijk_Sys'):
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.call(new_call_stack_suffix, target_addr)
            new_bbl_stack.push(new_call_stack_suffix, target_addr, target_addr)
        elif suc_jumpkind == "Ijk_Ret":
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.ret(call_stack_suffix, func_addr)
        elif suc_jumpkind == "Ijk_FakeRet":
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
        else:
            new_bbl_stack = entry_wrapper.bbl_stack_copy()
            new_bbl_stack.push(new_call_stack_suffix, func_addr, target_addr)

        new_path = self.project.factory.path(new_state)
        # We might have changed the mode for this basic block
        # before. Make sure it is still running in 'fastpath' mode
        # new_exit.state = self.project.simos.prepare_call_state(new_exit.state, initial_state=saved_state)
        new_path.state.set_mode('fastpath')
        pw = EntryWrapper(new_path,
                          self._context_sensitivity_level,
                          simrun_key,
                          suc_exit_stmt_idx,
                          call_stack=new_call_stack,
                          bbl_stack=new_bbl_stack,
                          cancelled_pending_entry=cancelled_pending_entry
                          )

        # Generate new exits
        if suc_jumpkind == "Ijk_Ret":
            # This is the real return exit
            # Check if this retn is inside our pending_exits set
            if new_tpl in self._pending_entries:

                # The fake ret is confirmed (since we are returning from the function it calls). Create an edge for it
                # in the graph. However, we don't want to create the edge here, since the destination node hasn't been
                # created yet at this moment. So we save the pending entry to the real entry, and create the FakeRet
                # edge when that entry is processed later.
                pending_entry = self._pending_entries[new_tpl]
                # TODO: is it possible that the cancelled_pending_entry has already been assigned before?
                pw.cancelled_pending_entry = pending_entry

                del self._pending_entries[new_tpl]

            successor_status[state] = "Appended"

        elif suc_jumpkind == "Ijk_FakeRet":
            # This is the default "fake" retn that generated at each
            # call. Save them first, but don't process them right
            # away
            # st = self.project.simos.prepare_call_state(new_state, initial_state=saved_state)
            st = new_state
            st.set_mode('fastpath')

            pw = None # clear the EntryWrapper
            pe = PendingExit(extra_info['call_target'], st, simrun_key, suc_exit_stmt_idx, new_bbl_stack,
                             new_call_stack
                             )
            self._pending_entries[new_tpl] = pe
            successor_status[state] = "Pended"

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
            successor_status[state] = "Appended"

        if extra_info['is_call_jump'] and extra_info['call_target'] in self._non_returning_functions:
            extra_info['skip_fakeret'] = True

        if pw:
            self._entries.append(pw)

    # SimAction handling

    def _handle_actions(self, state, current_run, func, sp_addr, accessed_registers):
        se = state.se

        if func is not None and sp_addr is not None:

            # Fix the stack pointer (for example, skip the return address on the stack)
            new_sp_addr = sp_addr + self.project.arch.call_sp_fix

            actions = [a for a in state.log.actions if a.bbl_addr == current_run.addr]

            for a in actions:
                if a.type == "mem" and a.action == "read":
                    try:
                        addr = se.exactly_int(a.addr.ast, default=0)
                    except claripy.ClaripyError:
                        continue
                    if (self.project.arch.call_pushes_ret and addr >= new_sp_addr) or \
                            (not self.project.arch.call_pushes_ret and addr >= new_sp_addr):
                        # TODO: What if a variable locates higher than the stack is modified as well? We probably want
                        # to make sure the accessing address falls in the range of stack
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
                "handle_actions: Function not found, or stack pointer is None. It might indicates unbalanced stack.")

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
            addr = self._simrun_key_addr(node_key)
            func_addr = self._simrun_key_current_func_addr(node_key)
            if func_addr is None:
                # We'll have to use the current SimRun address instead
                # TODO: Is it really OK?
                func_addr = self._simrun_key_addr(node_key)

            pt = CFGNode(self._simrun_key_addr(node_key),
                         None,
                         self,
                         callstack_key=self._simrun_key_callstack_key(node_key),
                         input_state=None,
                         simprocedure_name="PathTerminator",
                         function_address=func_addr)
            if self._keep_state:
                # We don't have an input state available for it (otherwise we won't have to create a
                # PathTerminator). This is just a trick to make get_any_irsb() happy.
                pt.input_state = self.project.factory.entry_state()
                pt.input_state.ip = pt.addr
            self._nodes[node_key] = pt
            self._nodes_by_addr[pt.addr].append((node_key, pt))

            if isinstance(self.project.arch, ArchARM) and addr % 2 == 1:
                self._thumb_addrs.add(addr)
                self._thumb_addrs.add(addr - 1)

            l.debug("SimRun key %s does not exist. Create a PathTerminator instead.",
                    self._simrun_key_repr(node_key))

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

    def _update_function_transition_graph(self, src_node_key, dst_node_key, jumpkind='Ijk_Boring'):
        """
        Update transition graphs of functions in function manager based on information passed in.

        :param str jumpkind: Jumpkind.
        :param CFGNode src_node: Source CFGNode
        :param CFGNode dst_node: Destionation CFGNode
        :param int ret_addr: The theoretical return address for calls
        :return: None
        """

        dst_node = self._graph_get_node(dst_node_key, terminator_for_nonexistent_node=True)
        if src_node_key is None:
            self.kb.functions.function(dst_node.function_address, create=True)._register_nodes(dst_node.to_codenode())
            return

        src_node = self._graph_get_node(src_node_key, terminator_for_nonexistent_node=True)

        # Update the transition graph of current function
        if jumpkind == "Ijk_Call":
            ret_addr = src_node.return_target
            ret_node = self.kb.functions.function(
                src_node.function_address,
                create=True
            )._get_block(ret_addr).codenode if ret_addr else None

            if ret_node is None:
                l.warning("Unknown return site for call to %#x at call-site %#x", dst_node.addr, src_node.addr)

            self.kb.functions._add_call_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_addr=dst_node.addr,
                retn_node=ret_node,
                syscall=False
            )

        if jumpkind.startswith('Ijk_Sys'):

            self.kb.functions._add_call_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_addr=dst_node.addr,
                retn_node=src_node.to_codenode(),  # For syscalls, they are returning to the address of themselves
                syscall=True,
            )

        elif jumpkind == 'Ijk_Ret':
            # Create a return site for current function
            self.kb.functions._add_return_from(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_node=dst_node.to_codenode(),
            )

            # Create a returning edge in the caller function
            self.kb.functions._add_return_from_call(
                function_addr=dst_node.function_address,
                src_function_addr=src_node.function_address,
                to_node=dst_node.to_codenode()
            )

        elif jumpkind == 'Ijk_FakeRet':
            self.kb.functions._add_fakeret_to(
                function_addr=src_node.function_address,
                from_node=src_node.to_codenode(),
                to_node=dst_node.to_codenode()
            )

        elif jumpkind == 'Ijk_Boring':

            src_obj = self.project.loader.addr_belongs_to_object(src_node.addr)
            dest_obj = self.project.loader.addr_belongs_to_object(dst_node.addr)

            if src_obj is dest_obj:

                # It's a normal transition
                self.kb.functions._add_transition_to(
                    function_addr=src_node.function_address,
                    from_node=src_node.to_codenode(),
                    to_node=dst_node.to_codenode()
                )

            else:
                self.kb.functions._add_call_to(
                    function_addr=src_node.function_address,
                    from_node=src_node.to_codenode(),
                    to_addr=dst_node.addr,
                    retn_node=None,  # TODO
                    syscall=False
                )

    def _add_additional_edges(self, simrun, cfg_node, successors):
        """

        :return:
        """

        # If we have additional edges for this SimRun, add them in
        addr = cfg_node.addr

        if addr in self._additional_edges:
            dests = self._additional_edges[addr]
            for dst in dests:
                if isinstance(simrun, simuvex.SimIRSB):
                    base_state = simrun.default_exit.copy()
                else:
                    if successors:
                        # We try to use the first successor.
                        base_state = successors[0].copy()
                    else:
                        # The SimProcedure doesn't have any successor (e.g. it's a PathTerminator)
                        # We'll use its input state instead
                        base_state = simrun.initial_state
                base_state.ip = dst
                # TODO: Allow for sp adjustments
                successors.append(base_state)
                l.debug("Additional jump target 0x%x for simrun %s is appended.", dst, simrun)

        return successors

    def _remove_non_return_edges(self):
        """
        Remove those return_from_call edges that actually do not return due to
        calling some not-returning functions.
        :return: None
        """
        for func in self.kb.functions.values():
            graph = func.transition_graph
            all_return_edges = [(u, v) for (u, v, data) in graph.edges(data=True) if data['type'] == 'return_from_call']
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
                            if jumpkind == 'Ijk_FakeRet' and successor.addr == return_to_addr:
                                self.remove_edge(n, successor)

                                # Remove all dangling nodes
                                # wcc = list(networkx.weakly_connected_components(graph))
                                # for nodes in wcc:
                                #    if func.startpoint not in nodes:
                                #        graph.remove_nodes_from(nodes)

    # Private methods - resolving indirect jumps

    def _resolve_indirect_jumps(self, simrun, cfg_node, func_addr, successors, error_occurred, simrun_info_collection):
        """

        :return:
        """

        # Try to resolve indirect jumps with advanced backward slicing (if enabled)
        if isinstance(simrun, simuvex.SimIRSB) and \
                self._is_indirect_jump(cfg_node, simrun):
            l.debug('IRSB 0x%x has an indirect jump as its default exit', simrun.addr)

            # Throw away all current paths whose target doesn't make sense
            old_successors = successors[::]
            successors = []
            for i, suc in enumerate(old_successors):

                if suc.se.symbolic(suc.ip):
                    # It's symbolic. Take it, and hopefully we can resolve it later
                    successors.append(suc)

                else:
                    # It's concrete. Does it make sense?
                    ip_int = suc.se.exactly_int(suc.ip)

                    if self._is_address_executable(ip_int) or \
                            self.project.is_hooked(ip_int):
                        successors.append(suc)

                    else:
                        l.info('%s: an obviously incorrect successor %d/%d (%#x) is ditched',
                               cfg_node,
                               i + 1, len(old_successors),
                               ip_int)

            # We need input states to perform backward slicing
            if self._advanced_backward_slicing and self._keep_state:

                # Optimization: make sure we only try to resolve an indirect jump if any of the following criteria holds
                # - It's a jump (Ijk_Boring), and its target is either fully symbolic, or its resolved target is within
                #   the current binary
                # - It's a call (Ijk_Call), and its target is fully symbolic
                # TODO: This is very hackish, please refactor this part of code later
                should_resolve = True
                legit_successors = [suc for suc in successors if suc.scratch.jumpkind in ('Ijk_Boring', 'Ijk_Call')]
                if legit_successors:
                    legit_successor = legit_successors[0]
                    if legit_successor.ip.symbolic:
                        if not legit_successor.scratch.jumpkind == 'Ijk_Call':
                            should_resolve = False
                    else:
                        if legit_successor.scratch.jumpkind == 'Ijk_Call':
                            should_resolve = False
                        else:
                            concrete_target = legit_successor.se.any_int(legit_successor.ip)
                            if not self.project.loader.addr_belongs_to_object(
                                    concrete_target) is self.project.loader.main_bin:
                                should_resolve = False

                else:
                    # No interesting successors... skip
                    should_resolve = False

                # TODO: Handle those successors
                if not should_resolve:
                    l.debug("This might not be an indirect jump that has multiple targets. Skipped.")

                else:
                    more_successors = self._resolve_indirect_jump(cfg_node, simrun, func_addr)

                    if len(more_successors):
                        # Remove the symbolic successor
                        # TODO: Now we are removing all symbolic successors. Is it possible
                        # TODO: that there is more than one symbolic successor?
                        all_successors = [suc for suc in successors if not suc.se.symbolic(suc.ip)]
                        # Insert new successors
                        # We insert new successors in the beginning of all_successors list so that we don't break the
                        # assumption that Ijk_FakeRet is always the last element in the list
                        for suc_addr in more_successors:
                            a = simrun.default_exit.copy()
                            a.ip = suc_addr
                            all_successors.insert(0, a)

                        l.debug('The indirect jump is successfully resolved.')

                        self.kb._resolved_indirect_jumps.add(simrun.addr)

                    else:
                        l.debug('We failed to resolve the indirect jump.')
                        self.kb._unresolved_indirect_jumps.add(simrun.addr)

            else:
                if not successors:
                    l.debug('We cannot resolve the indirect jump without advanced backward slicing enabled: %s',
                            cfg_node)

        # Try to find more successors if we failed to resolve the indirect jump before
        if not error_occurred and (cfg_node.is_simprocedure or self._is_indirect_jump(cfg_node, simrun)):
            has_call_jumps = any([suc_state.scratch.jumpkind == 'Ijk_Call' for suc_state in successors])
            if has_call_jumps:
                concrete_successors = [suc_state for suc_state in successors if
                                       suc_state.scratch.jumpkind != 'Ijk_FakeRet' and not suc_state.se.symbolic(
                                           suc_state.ip)]
            else:
                concrete_successors = [suc_state for suc_state in successors if
                                       not suc_state.se.symbolic(suc_state.ip)]
            symbolic_successors = [suc_state for suc_state in successors if suc_state.se.symbolic(suc_state.ip)]

            resolved = len(symbolic_successors) == 0
            if len(symbolic_successors) > 0:
                for suc in symbolic_successors:
                    if simuvex.o.SYMBOLIC in suc.options:
                        targets = suc.se.any_n_int(suc.ip, 32)
                        if len(targets) < 32:
                            all_successors = []
                            resolved = True
                            for t in targets:
                                new_ex = suc.copy()
                                new_ex.ip = suc.se.BVV(t, suc.ip.size())
                                all_successors.append(new_ex)
                        else:
                            break

            if not resolved and (
                        (len(symbolic_successors) > 0 and len(concrete_successors) == 0) or
                        (not cfg_node.is_simprocedure and self._is_indirect_jump(cfg_node, simrun))
            ):
                l.debug("%s has an indirect jump. See what we can do about it.", cfg_node)

                if isinstance(simrun, simuvex.SimProcedure) and \
                        simrun.ADDS_EXITS:
                    # Skip those SimProcedures that don't create new SimExits
                    l.debug('We got a SimProcedure %s in fastpath mode that creates new exits.', simrun)
                    if self._enable_symbolic_back_traversal:
                        successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)
                        # mark jump as resolved if we got successors
                        if len(successors):
                            self.kb._resolved_indirect_jumps.add(simrun.addr)
                        else:
                            self.kb._unresolved_indirect_jumps.add(simrun.addr)
                        l.debug("Got %d concrete exits in symbolic mode.", len(successors))
                    else:
                        self.kb._unresolved_indirect_jumps.add(simrun.addr)
                        # keep fake_rets
                        successors = [s for s in successors if s.scratch.jumpkind == "Ijk_FakeRet"]

                elif isinstance(simrun, simuvex.SimIRSB) and \
                        any([ex.scratch.jumpkind != 'Ijk_Ret' for ex in successors]):
                    # We cannot properly handle Return as that requires us start execution from the caller...
                    l.debug("Try traversal backwards in symbolic mode on %s.", cfg_node)
                    if self._enable_symbolic_back_traversal:
                        successors = self._symbolically_back_traverse(simrun, simrun_info_collection, cfg_node)

                        # Remove successors whose IP doesn't make sense
                        successors = [suc for suc in successors
                                          if self._is_address_executable(suc.se.exactly_int(suc.ip))]

                        # mark jump as resolved if we got successors
                        if len(successors):
                            self.kb._resolved_indirect_jumps.add(simrun.addr)
                        else:
                            self.kb._unresolved_indirect_jumps.add(simrun.addr)
                        l.debug('Got %d concrete exits in symbolic mode', len(successors))
                    else:
                        self.kb._unresolved_indirect_jumps.add(simrun.addr)
                        successors = []

                elif len(successors) > 0 and all([ex.scratch.jumpkind == 'Ijk_Ret' for ex in successors]):
                    l.debug('All exits are returns (Ijk_Ret). It will be handled by pending exits.')

                else:
                    l.warning('It seems that we cannot resolve this indirect jump: %s', cfg_node)
                    self.kb._unresolved_indirect_jumps.add(simrun.addr)

        return successors

    def _resolve_indirect_jump(self, cfgnode, simirsb, current_function_addr):
        """
        Try to resolve an indirect jump by slicing backwards
        """

        l.debug("Resolving indirect jump at IRSB %s", simirsb)

        # Let's slice backwards from the end of this exit
        next_tmp = simirsb.irsb.next.tmp
        stmt_id = [i for i, s in enumerate(simirsb.irsb.statements)
                   if isinstance(s, pyvex.IRStmt.WrTmp) and s.tmp == next_tmp][0]

        cdg = self.project.analyses.CDG(cfg=self)
        ddg = self.project.analyses.DDG(cfg=self, start=current_function_addr, call_depth=0)

        bc = self.project.analyses.BackwardSlice(self, cdg, ddg, targets=[(cfgnode, stmt_id)], same_function=True)
        taint_graph = bc.taint_graph
        # Find the correct taint
        next_nodes = [cl for cl in taint_graph.nodes() if cl.simrun_addr == simirsb.addr]

        if not next_nodes:
            l.error('The target exit is not included in the slice. Something is wrong')
            return []

        next_node = next_nodes[0]

        # Get the weakly-connected subgraph that contains `next_node`
        all_subgraphs = networkx.weakly_connected_component_subgraphs(taint_graph)
        starts = set()
        for subgraph in all_subgraphs:
            if next_node in subgraph:
                # Make sure there is no symbolic read...
                # FIXME: This is an over-approximation. We should try to limit the starts more
                nodes = [n for n in subgraph.nodes() if subgraph.in_degree(n) == 0]
                for n in nodes:
                    starts.add(n.simrun_addr)

        # Execute the slice
        successing_addresses = set()
        annotated_cfg = bc.annotated_cfg()
        for start in starts:
            l.debug('Start symbolic execution at 0x%x on program slice.', start)
            # Get the state from our CFG
            node = self.get_any_node(start)
            if node is None:
                # Well, we have to live with an empty state
                p = self.project.factory.path(self.project.factory.blank_state(addr=start))
            else:
                base_state = node.input_state.copy()
                base_state.set_mode('symbolic')
                base_state.ip = start

                # Clear all initial taints (register values, memory values, etc.)
                initial_nodes = [n for n in bc.taint_graph.nodes() if bc.taint_graph.in_degree(n) == 0]
                for cl in initial_nodes:
                    # Iterate in all actions of this node, and pick corresponding actions
                    cfg_nodes = self.get_all_nodes(cl.simrun_addr)
                    for n in cfg_nodes:
                        if not n.final_states:
                            continue
                        actions = [ac for ac in n.final_states[0].log.actions
                                   # Normally it's enough to only use the first final state
                                   if ac.bbl_addr == cl.simrun_addr and
                                   ac.stmt_idx == cl.stmt_idx
                                   ]
                        for ac in actions:
                            if not hasattr(ac, 'action'):
                                continue
                            if ac.action == 'read':
                                if ac.type == 'mem':
                                    unconstrained_value = base_state.se.Unconstrained('unconstrained',
                                                                                      ac.size.ast * 8)
                                    base_state.memory.store(ac.addr,
                                                            unconstrained_value,
                                                            endness=self.project.arch.memory_endness)
                                elif ac.type == 'reg':
                                    unconstrained_value = base_state.se.Unconstrained('unconstrained',
                                                                                      ac.size.ast * 8)
                                    base_state.registers.store(ac.offset,
                                                               unconstrained_value,
                                                               endness=self.project.arch.register_endness)

                # Clear the constraints!
                base_state.release_plugin('solver_engine')
                p = self.project.factory.path(base_state)

            # For speed concerns, we are limiting the timeout for z3 solver to 5 seconds. It will be restored afterwards
            old_timeout = p.state.se._solver.timeout
            p.state.se._solver.timeout = 5000

            sc = self.project.surveyors.Slicecutor(annotated_cfg, start=p, max_loop_iterations=1).run()

            # Restore the timeout!
            p.state.se._solver.timeout = old_timeout

            if sc.cut or sc.deadended:
                all_deadended_paths = sc.cut + sc.deadended
                for p in all_deadended_paths:
                    if p.addr == simirsb.addr:
                        # We want to get its successors
                        successing_paths = p.step()
                        for sp in successing_paths:
                            successing_addresses.add(sp.addr)

            else:
                l.debug("Cannot determine the exit. You need some better ways to recover the exits :-(")

        l.debug('Resolution is done, and we have %d new successors.', len(successing_addresses))

        return list(successing_addresses)

    def _symbolically_back_traverse(self, current_simrun, simrun_info_collection, cfg_node):

        class register_protector(object):
            def __init__(self, reg_offset, info_collection):
                self._reg_offset = reg_offset
                self._info_collection = info_collection

            def write_persistent_register(self, state_):
                if state_.inspect.address is None:
                    l.error('state.inspect.address is None. It will be fixed by Yan later.')
                    return

                if state_.registers.load(self._reg_offset).symbolic:
                    current_run = state_.inspect.address
                    if current_run in self._info_collection and \
                            not state_.se.symbolic(self._info_collection[current_run][self._reg_offset]):
                        l.debug("Overwriting %s with %s", state_.registers.load(self._reg_offset),
                                self._info_collection[current_run][self._reg_offset])
                        state_.registers.store(
                            self._reg_offset,
                            self._info_collection[current_run][self._reg_offset]
                        )

        l.debug("Start back traversal from %s", current_simrun)

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
        while len(concrete_exits) == 0 and path_length < 5 and keep_running:
            path_length += 1
            queue = [cfg_node]
            avoid = set()
            for _ in xrange(path_length):
                new_queue = []
                for n in queue:
                    successors = temp_cfg.successors(n)
                    for suc in successors:
                        jk = temp_cfg.get_edge_data(n, suc)['jumpkind']
                        if jk != 'Ijk_Ret':
                            # We don't want to trace into libraries
                            predecessors = temp_cfg.predecessors(suc)
                            avoid |= set([p.addr for p in predecessors if p is not n])
                            new_queue.append(suc)
                queue = new_queue

            if path_length <= 1:
                continue

            for n in queue:
                # Start symbolic exploration from each block
                state = self.project.factory.blank_state(addr=n.addr,
                                                         mode='symbolic',
                                                         add_options={
                                                                         simuvex.o.DO_RET_EMULATION,
                                                                         simuvex.o.CONSERVATIVE_READ_STRATEGY,
                                                                     } | simuvex.o.resilience_options
                                                         )
                # Avoid concretization of any symbolic read address that is over a certain limit
                # TODO: test case is needed for this option

                # Set initial values of persistent regs
                if n.addr in simrun_info_collection:
                    for reg in state.arch.persistent_regs:
                        state.registers.store(reg, simrun_info_collection[n.addr][reg])
                for reg in state.arch.persistent_regs:
                    reg_protector = register_protector(reg, simrun_info_collection)
                    state.inspect.add_breakpoint('reg_write',
                                                 simuvex.BP(
                                                     simuvex.BP_AFTER,
                                                     reg_write_offset=state.arch.registers[reg][0],
                                                     action=reg_protector.write_persistent_register
                                                 )
                                                 )
                result = self.project.surveyors.Explorer(
                    start=self.project.factory.path(state),
                    find=(current_simrun.addr,),
                    avoid=avoid,
                    max_repeats=10,
                    max_depth=path_length
                ).run()
                if result.found:
                    if not result.found[0].errored and len(result.found[0].step()) > 0:
                        # Make sure we don't throw any exception here by checking the path.errored attribute first
                        keep_running = False
                        concrete_exits.extend([s for s in result.found[0].next_run.flat_successors])
                        concrete_exits.extend([s for s in result.found[0].next_run.unsat_successors])
                if keep_running:
                    l.debug('Step back for one more run...')

        # Make sure these successors are actually concrete
        # We just use the ip, persistent registers, and jumpkind to initialize the original unsat state
        # TODO: It works for jumptables, but not for calls. We should also handle changes in sp
        new_concrete_successors = []
        for c in concrete_exits:
            unsat_state = current_simrun.unsat_successors[0].copy()
            unsat_state.scratch.jumpkind = c.scratch.jumpkind
            for reg in unsat_state.arch.persistent_regs + ['ip']:
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
                raise AngrCFGError('The impossible happened. Please report to Fish.')

        symbolic_initial_state = self.project.factory.entry_state(mode='symbolic')
        if fastpath_state is not None:
            symbolic_initial_state = self.project._simos.prepare_call_state(fastpath_state,
                                                                           initial_state=symbolic_initial_state)

        # Create a temporary block
        try:
            tmp_block = self.project.factory.block(function_addr)
        except (simuvex.SimError, AngrError):
            return None

        num_instr = tmp_block.instructions - 1

        symbolic_initial_state.ip = function_addr
        path = self.project.factory.path(symbolic_initial_state)
        try:
            simrun = self.project.factory.sim_run(path.state, num_inst=num_instr)
        except (simuvex.SimError, AngrError):
            return None

        # We execute all but the last instruction in this basic block, so we have a cleaner
        # state
        # Start execution!
        exits = simrun.flat_successors + simrun.unsat_successors

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

    def _search_for_function_hints(self, simrun):
        """
        Scan for constants that might be used as exit targets later, and add
        them into pending_exits
        """

        function_hints = []
        if isinstance(simrun, simuvex.SimIRSB) and simrun.successors:
            successor = simrun.successors[0]
            for action in successor.log.actions:
                if action.type == 'reg' and action.offset == self.project.arch.ip_offset:
                    # Skip all accesses to IP registers
                    continue
                elif action.type == 'exit':
                    # only consider read/write actions
                    continue

                # Enumerate actions
                data = action.data
                if data is not None:
                    # TODO: Check if there is a proper way to tell whether this const falls in the range of code
                    # TODO: segments
                    # Now let's live with this big hack...
                    try:
                        const = successor.se.exactly_n_int(data.ast, 1)[0]
                    except:  # pylint: disable=bare-except
                        continue

                    if self._is_address_executable(const):
                        if self._pending_function_hints is not None and const in self._pending_function_hints:
                            continue

                        # target = const
                        # tpl = (None, None, target)
                        # st = self.project.simos.prepare_call_state(self.project.initial_state(mode='fastpath'),
                        #                                           initial_state=saved_state)
                        # st = self.project.initial_state(mode='fastpath')
                        # exits[tpl] = (st, None, None)

                        function_hints.append(const)

            l.info('Got %d possible exits from %s, including: %s', len(function_hints), simrun,
                   ", ".join(["0x%x" % f for f in function_hints]))

        return function_hints

    # Private methods - creation of stuff (SimRun, CFGNode, call-stack, etc.)

    def _get_simrun(self, addr, current_entry, current_function_addr=None):
        error_occurred = False
        state = current_entry.state
        saved_state = current_entry.state  # We don't have to make a copy here
        try:
            if not self._keep_state and \
                    self.project.is_hooked(addr) and \
                    not self.project._sim_procedures[addr][0] is simuvex.s_procedure.SimProcedureContinuation and \
                    not self.project._sim_procedures[addr][0].ADDS_EXITS and \
                    not self.project._sim_procedures[addr][0].NO_RET:
                # DON'T CREATE USELESS SIMPROCEDURES if we don't care about the accuracy of states
                # When generating CFG, a SimProcedure will not be created as it is but be created as a
                # ReturnUnconstrained stub if it satisfies the following conditions:
                # - It doesn't add any new exits.
                # - It returns as normal.
                # In this way, we can speed up the CFG generation by quite a lot as we avoid simulating
                # those functions like read() and puts(), which has no impact on the overall control flow at all.
                #
                # Special notes about _SimProcedureContinuation_ instances. Any SimProcedure that corresponds to the
                # SimProcedureContinuation we see here adds new exits, otherwise the original SimProcedure wouldn't have
                # been executed anyway. Hence it's reasonable for us to always simulate a SimProcedureContinuation
                # instance.

                old_proc = self.project._sim_procedures[addr][0]
                old_name = None
                if old_proc == simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"]:
                    proc_kwargs = self.project._sim_procedures[addr][1]
                    if 'resolves' in proc_kwargs:
                        old_name = proc_kwargs['resolves']

                if old_name is None:
                    old_name = old_proc.__name__.split('.')[-1]

                sim_run = simuvex.procedures.SimProcedures["stubs"]["ReturnUnconstrained"](
                    state,
                    addr=addr,
                    sim_kwargs={'resolves': "%s" % old_name}
                )
            else:
                jumpkind = state.scratch.jumpkind
                jumpkind = 'Ijk_Boring' if jumpkind is None else jumpkind
                sim_run = self.project.factory.sim_run(current_entry.state, jumpkind=jumpkind)

        except (simuvex.SimFastPathError, simuvex.SimSolverModeError) as ex:

            if saved_state.mode == 'fastpath':
                # Got a SimFastPathError or SimSolverModeError in FastPath mode.
                # We wanna switch to symbolic mode for current IRSB.
                l.debug('Switch to symbolic mode for address 0x%x', addr)
                # Make a copy of the current 'fastpath' state

                l.debug('Symbolic jumps at basic block 0x%x.' % addr)

                new_state = None
                if addr != current_function_addr:
                    new_state = self._get_symbolic_function_initial_state(current_function_addr)

                if new_state is None:
                    new_state = current_entry.state.copy()
                    new_state.set_mode('symbolic')
                new_state.options.add(simuvex.o.DO_RET_EMULATION)
                # Remove bad constraints
                # FIXME: This is so hackish...
                new_state.se._solver.constraints = [c for c in new_state.se.constraints if
                                                    c.op != 'I' or c.args[0] is not False]
                new_state.se._solver._result = None
                # Swap them
                saved_state, current_entry.state = current_entry.state, new_state
                sim_run, error_occurred, _ = self._get_simrun(addr, current_entry)

            else:
                # Got a SimSolverModeError in symbolic mode. We are screwed.
                # Skip this IRSB
                l.debug("Caught a SimIRSBError %s. Don't panic, this is usually expected.", ex)
                error_occurred = True
                sim_run = \
                    simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                        state, addr=addr)

        except simuvex.SimIRSBError:
            # It's a tragedy that we came across some instructions that VEX
            # does not support. I'll create a terminating stub there
            l.debug("Caught a SimIRSBError during CFG recovery. Creating a PathTerminator.", exc_info=True)
            error_occurred = True
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)

        except claripy.ClaripyError:
            l.debug("Caught a ClaripyError during CFG recovery. Don't panic, this is usually expected.", exc_info=True)
            error_occurred = True
            # Generate a PathTerminator to terminate the current path
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)

        except simuvex.SimError:
            l.debug("Caught a SimError when during CFG recovery. Don't panic, this is usually expected.", exc_info=True)

            error_occurred = True
            # Generate a PathTerminator to terminate the current path
            sim_run = \
                simuvex.procedures.SimProcedures["stubs"]["PathTerminator"](
                    state, addr=addr)

        except AngrError:
            section = self.project.loader.main_bin.find_section_containing(addr)
            if section is None:
                sec_name = 'No section'
            else:
                sec_name = section.name
            # AngrError shouldn't really happen though
            l.error("Caught an AngrError during CFG recovery at %#x (%s)",
                    addr, sec_name, exc_info=True)
            # We might be on a wrong branch, and is likely to encounter the
            # "No bytes in memory xxx" exception
            # Just ignore it
            error_occurred = True
            sim_run = None

        return sim_run, error_occurred, saved_state

    def _create_new_call_stack(self, addr, all_entries, entry_wrapper, exit_target, jumpkind):
        if jumpkind == "Ijk_Call" or jumpkind.startswith('Ijk_Sys'):
            new_call_stack = entry_wrapper.call_stack_copy()
            # Notice that in ARM, there are some freaking instructions
            # like
            # BLEQ <address>
            # It should give us three exits: Ijk_Call, Ijk_Boring, and
            # Ijk_Ret. The last exit is simulated.
            # Notice: We assume the last exit is the simulated one
            if len(all_entries) > 1 and all_entries[-1].scratch.jumpkind == "Ijk_FakeRet":
                se = all_entries[-1].se
                retn_target_addr = se.exactly_int(all_entries[-1].ip, default=0)
                sp = se.exactly_int(all_entries[-1].regs.sp, default=0)

                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr,
                                    stack_pointer=sp)

            elif jumpkind.startswith('Ijk_Sys') and len(all_entries) == 1:
                # This is a syscall. It returns to the same address as itself (with a different jumpkind)
                retn_target_addr = exit_target
                se = all_entries[0].se
                sp = se.exactly_int(all_entries[0].regs.sp, default=0)
                new_call_stack.call(addr, exit_target,
                                    retn_target=retn_target_addr,
                                    stack_pointer=sp)

            else:
                # We don't have a fake return exit available, which means
                # this call doesn't return.
                new_call_stack.clear()
                se = all_entries[-1].se
                sp = se.exactly_int(all_entries[-1].regs.sp, default=0)

                new_call_stack.call(addr, exit_target, retn_target=None, stack_pointer=sp)

        elif jumpkind == "Ijk_Ret":
            # Normal return
            new_call_stack = entry_wrapper.call_stack_copy()
            new_call_stack.ret(exit_target)

            se = all_entries[-1].se
            sp = se.exactly_int(all_entries[-1].regs.sp, default=0)
            old_sp = entry_wrapper.current_stack_pointer

            # Calculate the delta of stack pointer
            if sp is not None and old_sp is not None:
                delta = sp - old_sp
                func_addr = entry_wrapper.current_function_address

                if self.kb.functions.function(func_addr) is None:
                    # Create the function if it doesn't exist
                    # FIXME: But hell, why doesn't it exist in the first place?
                    l.error("Function 0x%x doesn't exist in function manager although it should be there." +
                            "Look into this issue later.",
                            func_addr)
                    self.kb.functions.function(func_addr, create=True)

                # Set sp_delta of the function
                self.kb.functions.function(func_addr, create=True).sp_delta = delta

        elif jumpkind == 'Ijk_FakeRet':
            # The fake return...
            new_call_stack = entry_wrapper.call_stack

        else:
            # although the jumpkind is not Ijk_Call, it may still jump to a new function... let's see
            if self.project.is_hooked(exit_target):
                hooker = self.project.hooked_by(exit_target)
                if not hooker is simuvex.procedures.stubs.UserHook.UserHook:
                    # if it's not a UserHook, it must be a function
                    # Update the function address of the most recent call stack frame
                    new_call_stack = entry_wrapper.call_stack_copy()
                    new_call_stack.current_function_address = exit_target

                else:
                    # TODO: We need a way to mark if a user hook is a function or not
                    # TODO: We can add a map in Project to store this information
                    # For now we are just assuming they are not functions, which is mostly the case
                    new_call_stack = entry_wrapper.call_stack

            else:
                # Normal control flow transition
                new_call_stack = entry_wrapper.call_stack

        return new_call_stack

    def _create_cfgnode(self, simrun, call_stack_suffix, func_addr):
        """
        Create a context-sensitive CFGNode instance for a specific SimRun.

        :param simuvex.SimRun simrun: The SimRun object.
        :param tuple call_stack_suffix: The call stack suffix
        :param int func_addr: Address of the current function
        :return: The CFGNode instance
        :rtype: CFGNode
        """

        # Determine whether this is a syscall
        if isinstance(simrun, simuvex.SimProcedure) and simrun.IS_SYSCALL is True:
            is_syscall = True
            syscall = simrun.__class__.__name__
        else:
            is_syscall = False
            syscall = None

        if isinstance(simrun, simuvex.SimProcedure):
            simproc_name = simrun.__class__.__name__.split('.')[-1]
            if simproc_name == "ReturnUnconstrained":
                simproc_name = simrun.resolves

            no_ret = False
            if syscall is not None and simrun.NO_RET:
                no_ret = True

            cfg_node = CFGNode(simrun.addr,
                               None,
                               self,
                               callstack_key=call_stack_suffix,
                               input_state=None,
                               simprocedure_name=simproc_name,
                               syscall_name=syscall,
                               no_ret=no_ret,
                               is_syscall=is_syscall,
                               syscall=syscall,
                               function_address=simrun.addr)

        else:
            cfg_node = CFGNode(simrun.addr,
                               simrun.irsb.size,
                               self,
                               callstack_key=call_stack_suffix,
                               input_state=None,
                               is_syscall=is_syscall,
                               syscall=syscall,
                               simrun=simrun,
                               function_address=func_addr)

        return cfg_node

    # Private methods - loops and graph normalization

    def _detect_loop(self, sim_run, new_tpl, simrun_key, new_call_stack_suffix, new_addr, new_jumpkind,
                     current_exit_wrapper, current_function_addr):
        """
        Loop detection.

        :param sim_run:
        :param new_tpl:
        :param simrun_key:
        :param new_call_stack_suffix:
        :param new_addr:
        :param new_jumpkind:
        :param current_exit_wrapper:
        :param current_function_addr:
        :return:
        """
        assert isinstance(sim_run, simuvex.SimIRSB)

        if new_jumpkind.startswith("Ijk_Sys"):
            return

        # Loop detection only applies to SimIRSBs
        # The most f****** case: An IRSB branches to itself
        if new_tpl == simrun_key:
            l.debug("%s is branching to itself. That's a loop.", sim_run)
            if (sim_run.addr, sim_run.addr) not in self._loop_back_edges_set:
                self._loop_back_edges_set.add((sim_run.addr, sim_run.addr))
                self._loop_back_edges.append((simrun_key, new_tpl))
        elif new_jumpkind != "Ijk_Call" and new_jumpkind != "Ijk_Ret" and \
                current_exit_wrapper.bbl_in_stack(
                    new_call_stack_suffix, current_function_addr, new_addr):
            '''
            There are two cases:
            # The loop header we found is a single IRSB that doesn't overlap with
            other IRSBs
            or
            # The loop header we found is a subset of the original loop header IRSB,
            as IRSBa could be inside IRSBb if they don't start at the same address but
            end at the same address
            We should take good care of these two cases.
            '''  # pylint:disable=W0105
            # First check if this is an overlapped loop header
            next_irsb = self._nodes[new_tpl]

            other_preds = set()

            for node_key, node in self._nodes_by_addr[next_irsb.addr]:
                predecessors = self.graph.predecessors(node)
                for pred in predecessors:
                    if pred.addr != sim_run.addr:
                        other_preds.add(pred)

            if len(other_preds) > 0:
                is_overlapping = False
                for p in other_preds:
                    if isinstance(p, simuvex.SimIRSB):
                        if p.addr + p.irsb.size() == sim_run.addr + sim_run.irsb.size():
                            # Overlapping!
                            is_overlapping = True
                            break
                if is_overlapping:
                    # Case 2, it's overlapped with another loop header
                    # Pending. We should remove all exits from sim_run
                    self._overlapped_loop_headers.append(sim_run)
                    l.debug("Found an overlapped loop header %s", sim_run)
                else:
                    # Case 1
                    if (sim_run.addr, next_irsb.addr) not in self._loop_back_edges_set:
                        self._loop_back_edges_set.add((sim_run.addr, next_irsb.addr))
                        self._loop_back_edges.append((simrun_key, new_tpl))
                        l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)
            else:
                # Case 1, it's not over lapping with any other things
                if (sim_run.addr, next_irsb.addr) not in self._loop_back_edges_set:
                    self._loop_back_edges_set.add((sim_run.addr, next_irsb.addr))
                    self._loop_back_edges.append((simrun_key, new_tpl))
                l.debug("Found a loop, back edge %s --> %s", sim_run, next_irsb)

    def _normalize_loop_backedges(self):
        """
        Convert loop_backedges from tuples of simrun keys to real edges in self.graph.
        """

        loop_backedges = []

        for src_key, dst_key in self._loop_back_edges:
            src = self._nodes[src_key]
            dst = self._nodes[dst_key]

            loop_backedges.append((src, dst))

        self._loop_back_edges = loop_backedges

    # Private methods - function/procedure/subroutine analysis
    # Including calling convention, function arguments, etc.

    def _analyze_calling_conventions(self):
        """
        Concretely execute part of the function and watch the changes of sp
        :return: None
        """

        l.debug("Analyzing calling conventions of each function.")

        for func in self.kb.functions.values():
            if func.call_convention is not None:
                continue

            #
            # Refining arguments of a function by analyzing its call-sites
            #
            callsites = self._get_callsites(func.addr)
            self._refine_function_arguments(func, callsites)

            # Set the calling convention
            func.call_convention = func._match_cc()

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
                if jk == 'Ijk_FakeRet':
                    blocks_after = [s]
                    break

            regs_overwritten = set()
            stack_overwritten = set()
            regs_read = set()
            regs_written = set()

            try:
                # Execute the predecessor
                path = self.project.factory.path(
                    self.project.factory.blank_state(mode="fastpath", addr=blocks_ahead[0].addr))
                all_successors = path.next_run.successors + path.next_run.unsat_successors
                if len(all_successors) == 0:
                    continue

                suc = all_successors[0]
                se = suc.se
                # Examine the path log
                actions = suc.log.actions
                sp = se.exactly_int(suc.regs.sp, default=0) + self.project.arch.call_sp_fix
                for ac in actions:
                    if ac.type == "reg" and ac.action == "write":
                        regs_overwritten.add(ac.offset)
                    elif ac.type == "mem" and ac.action == "write":
                        addr = se.exactly_int(ac.addr.ast, default=0)
                        if (self.project.arch.call_pushes_ret and addr >= sp + self.project.arch.bits / 8) or \
                                (not self.project.arch.call_pushes_ret and addr >= sp):
                            offset = addr - sp
                            stack_overwritten.add(offset)

                func.prepared_registers.add(tuple(regs_overwritten))
                func.prepared_stack_variables.add(tuple(stack_overwritten))

            except (simuvex.SimError, AngrError):
                pass

            try:
                if len(blocks_after):
                    path = self.project.factory.path(
                        self.project.factory.blank_state(mode="fastpath", addr=blocks_after[0].addr))
                    all_successors = path.next_run.successors + path.next_run.unsat_successors
                    if len(all_successors) == 0:
                        continue

                    suc = all_successors[0]
                    actions = suc.log.actions
                    for ac in actions:
                        if ac.type == "reg" and ac.action == "read" and ac.offset not in regs_written:
                            regs_read.add(ac.offset)
                        elif ac.type == "reg" and ac.action == "write":
                            regs_written.add(ac.offset)

                    # Filter registers, remove unnecessary registers from the set
                    # regs_overwritten = self.project.arch.argument_registers.intersection(regs_overwritten)
                    regs_read = self.project.arch.argument_registers.intersection(regs_read)

                    func.registers_read_afterwards.add(tuple(regs_read))

            except (simuvex.SimError, AngrError):
                pass

    # Private methods - dominators and post-dominators

    def _immediate_dominators(self, node, target_graph=None, reverse_graph=False):
        if target_graph is None:
            target_graph = self.graph

        if node not in target_graph:
            raise AngrCFGError('Target node %s is not in graph.' % node)

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
    def _is_indirect_jump(_, simirsb):
        """
        Determine if this SimIRSB has an indirect jump as its exit
        """

        if simirsb.irsb.direct_next:
            # It's a direct jump
            return False

        if not (simirsb.irsb.jumpkind == 'Ijk_Call' or simirsb.irsb.jumpkind == 'Ijk_Boring'):
            # It's something else, like a ret of a syscall... we don't care about it
            return False

        return True

    @staticmethod
    def _generate_simrun_key(call_stack_suffix, simrun_addr, is_syscall):
        if not is_syscall:
            return call_stack_suffix + (simrun_addr, 'normal')
        else:
            return call_stack_suffix + (simrun_addr, 'syscall')

    @staticmethod
    def _simrun_key_repr(simrun_key):
        runtype = simrun_key[-1]
        addr = simrun_key[-2]

        callstack = []
        for i in xrange(0, len(simrun_key) - 2, 2):
            from_ = 'None' if simrun_key[i] is None else hex(simrun_key[i])
            to_ = 'None' if simrun_key[i + 1] is None else hex(simrun_key[i + 1])
            callstack.append("%s -> %s" % (from_, to_))

        s = "(%s), %s [%s]" % (", ".join(callstack), hex(addr), runtype)
        return s

    @staticmethod
    def _simrun_key_callstack_key(simrun_key):
        return simrun_key[: -2]

    @staticmethod
    def _simrun_key_addr(simrun_key):
        return simrun_key[-2]

    @staticmethod
    def _simrun_key_current_func_addr(simrun_key):
        """
        If we don't have any information about the caller, we have no way to get the address of the current function.

        :param simrun_key: SimRun key
        :return: The function address if there is one, or None if it's not possible to get
        """
        if len(simrun_key) > 2:
            return simrun_key[-3]
        else:
            return None

    #
    # Other private utility methods
    #

    def _push_unresolvable_run(self, simrun_address):
        self._unresolvable_runs.add(simrun_address)

    def _is_address_executable(self, address):
        """
        Check if the specific address is in one of the executable ranges.

        :param int address: The address
        :return: True if it's in an executable range, False otherwise
        """

        for r in self._executable_address_ranges:
            if address >= r[0] and address < r[1]:
                return True
        return False

    def _update_thumb_addrs(self, simrun, state):
        """

        :return:
        """

        # For ARM THUMB mode
        if isinstance(simrun, simuvex.SimIRSB) and state.thumb:
            self._thumb_addrs.update(simrun.imark_addrs())
            self._thumb_addrs.update(map(lambda x: x + 1, simrun.imark_addrs()))

    def _get_callsites(self, function_address):
        """
        Get where a specific function is called.
        :param function_address:    Address of the target function
        :return:                    A list of CFGNodes whose exits include a call/jump to the given function
        """

        all_predecessors = []

        nodes = self.get_all_nodes(function_address)
        for n in nodes:
            predecessors = self.get_predecessors(n)
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

        elif isinstance(begin, CFGNode) and isinstance(end, CFGNode):
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

register_analysis(CFGAccurate, 'CFGAccurate')
