import networkx

from claripy.utils.orderedset import OrderedSet

# errors
from ..errors import AngrForwardAnalysisError
# notices
from ..errors import AngrSkipEntryNotice, AngrDelayEntryNotice, AngrJobMergingFailureNotice, \
    AngrJobWideningFailureNotice
from .cfg.cfg_utils import CFGUtils


#
# Graph traversal
#

class GraphVisitor(object):
    """
    A graph visitor takes a node in the graph and returns its successors. Typically it visits a control flow graph, and
    returns successors of a CFGNode each time. This is the base class of all graph visitors.
    """
    def __init__(self):

        self._sorted_nodes = OrderedSet()
        self._reached_fixedpoint = set()

    #
    # Interfaces
    #

    def startpoints(self):
        """
        Get all start points to begin the traversal.

        :return: A list of startpoints that the traversal should begin with.
        """

        raise NotImplementedError()

    def successors(self, node):
        """
        Get successors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of successors.
        :rtype:      list
        """

        raise NotImplementedError()

    def predecessors(self, node):
        """
        Get predecessors of a node. The node should be in the graph.

        :param node: The node to work with.
        :return:     A list of predecessors.
        :rtype:      list
        """

        raise NotImplementedError()

    def sort_nodes(self, nodes=None):
        """
        Get a list of all nodes sorted in an optimal traversal order.

        :param iterable nodes: A collection of nodes to sort. If none, all nodes in the graph will be used to sort.
        :return:               A list of sorted nodes.
        :rtype:                list
        """

        raise NotImplementedError()

    #
    # Public methods
    #

    def nodes_iter(self):
        """
        Return an iterator of nodes following an optimal traversal order.

        :return:
        """

        sorted_nodes = self.sort_nodes()

        return iter(sorted_nodes)

    # Traversal

    def reset(self):
        """
        Reset the internal node traversal state. Must be called prior to visiting future nodes.

        :return: None
        """

        self._sorted_nodes.clear()
        self._reached_fixedpoint.clear()

        for n in self.sort_nodes():
            self._sorted_nodes.add(n)

    def next_node(self):
        """
        Get the next node to visit.

        :return: A node in the graph.
        """

        if not self._sorted_nodes:
            return None

        return self._sorted_nodes.pop(last=False)

    def all_successors(self, node, skip_reached_fixedpoint=False):
        """
        Returns all successors to the specific node.

        :param node: A node in the graph.
        :return:     A set of nodes that are all successors to the given node.
        :rtype:      set
        """

        successors = set()

        stack = [ node ]
        while stack:
            n = stack.pop()
            successors.add(n)
            stack.extend(succ for succ in self.successors(n) if
                         succ not in successors and
                            (not skip_reached_fixedpoint or succ not in self._reached_fixedpoint)
                         )

        return successors

    def revisit(self, node, include_self=True):
        """
        Revisit a node in the future. As a result, the successors to this node will be revisited as well.

        :param node: The node to revisit in the future.
        :return:     None
        """

        successors = self.successors(node) #, skip_reached_fixedpoint=True)

        if include_self:
            self._sorted_nodes.add(node)

        for succ in successors:
            self._sorted_nodes.add(succ)

        # reorder it
        self._sorted_nodes = OrderedSet(self.sort_nodes(self._sorted_nodes))

    def reached_fixedpoint(self, node):
        """
        Mark a node as reached fixed-point. This node as well as all its successors will not be visited in the future.

        :param node: The node to mark as reached fixed-point.
        :return:     None
        """

        self._reached_fixedpoint.add(node)


class FunctionGraphVisitor(GraphVisitor):
    def __init__(self, function):
        """

        :param knowledge.Function function:
        """

        super(FunctionGraphVisitor, self).__init__()

        self.function = function

        self.reset()

    def startpoints(self):

        return [ self.function.startpoint ]

    def successors(self, node):

        return self.function.graph.successors(node)

    def predecessors(self, node):

        return self.function.graph.predecessors(node)

    def sort_nodes(self, nodes=None):

        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.function.graph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes


class CallGraphVisitor(GraphVisitor):
    def __init__(self, callgraph):
        """

        :param networkx.DiGraph callgraph:
        """

        super(CallGraphVisitor, self).__init__()

        self.callgraph = callgraph

        self.reset()

    def startpoints(self):

        # TODO: make sure all connected components are covered

        start_nodes = [node for node in self.callgraph.nodes() if self.callgraph.in_degree(node) == 0]

        if not start_nodes:
            # randomly pick one
            start_nodes = [ self.callgraph.nodes()[0] ]

        return start_nodes

    def successors(self, node):

        return self.callgraph.successors(node)

    def predecessors(self, node):

        return self.callgraph.predecessors(node)

    def sort_nodes(self, nodes=None):

        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.callgraph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes


#
# Job info
#


class EntryInfo(object):
    """
    Stores information for each entry
    """
    def __init__(self, key, entry):
        self.key = key
        self.entries = [ (entry, '') ]

        self.narrowing_count = 0  # not used

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, o):
        return type(self) == type(o) and \
               self.key == o.key

    def __repr__(self):
        s = "<EntryInfo %s>" % (str(self.key))
        return s

    @property
    def entry(self):
        """
        Get the latest available entry.

        :return: The latest available entry.
        """

        ent, _ = self.entries[-1]
        return ent

    @property
    def merged_entries(self):
        for ent, entry_type in self.entries:
            if entry_type == 'merged':
                yield ent

    @property
    def widened_entries(self):
        for ent, entry_type in self.entries:
            if entry_type == 'widened':
                yield ent

    def add_entry(self, entry, merged=False, widened=False):
        """
        Appended a new entry to this EntryInfo node.
        :param entry: The new entry to append
        :param bool merged: Whether it is a merged entry or not.
        :param bool widened: Whether it is a widened entry or not.
        """

        entry_type = ''
        if merged:
            entry_type = 'merged'
        elif widened:
            entry_type = 'widened'
        self.entries.append((entry, entry_type))


class ForwardAnalysis(object):
    """
    This is my very first attempt to build a static forward analysis framework that can serve as the base of multiple
    static analyses in angr, including CFG analysis, VFG analysis, DDG, etc.

    In short, ForwardAnalysis performs a forward data-flow analysis by traversing the CFG (or the binary if a CFG is
    not available) and generating a graph with nodes linked with each program point (usually per basic-block, or SimRun
    in angr terms). A node on the graph stores analysis-specific information. For more information about nodes, take a
    look at the implementation of CFGNode.

    Feel free to discuss with me (Fish) if you have any suggestion or complaint!
    """

    def __init__(self, order_entries=False, allow_merging=False, allow_widening=False, status_callback=None,
                 graph_visitor=None
                 ):
        """
        Constructor

        :param bool order_entries: If all entries should be ordered or not.
        :param bool allow_merging: If entry merging is allowed.
        :param bool allow_widening: If entry widening is allowed.
        :param graph_visitor:       A graph visitor to provide successors.
        :type graph_visitor: GraphVisitor or None
        :return: None
        """

        self._order_entries = order_entries

        self._allow_merging = allow_merging
        self._allow_widening = allow_widening

        self._status_callback = status_callback

        self._graph_visitor = graph_visitor

        # sanity checks
        if self._allow_widening and not self._allow_merging:
            raise AngrForwardAnalysisError('Merging must be allowed if widening is allowed.')

        # Analysis progress control
        self._should_abort = False

        # All remaining entries
        self._job_info_list = [ ]

        # A map between entry key to entry. Entries with the same key will be merged by calling _merge_entries()
        self._entries_map = { }

        # A mapping between node and abstract state
        self._state_map = { }

        # The graph!
        # Analysis results (nodes) are stored here
        self._graph = networkx.DiGraph()

    #
    # Properties
    #

    @property
    def should_abort(self):
        """
        Should the analysis be terminated.
        :return: True/False
        """

        return self._should_abort

    @property
    def graph(self):
        return self._graph

    @property
    def entries(self):
        for entry_info in self._job_info_list:
            yield entry_info.entry

    #
    # Public methods
    #

    def abort(self):
        """
        Abort the analysis
        :return: None
        """

        self._should_abort = True

    #
    # Abstract interfaces
    #

    def _pre_analysis(self):
        raise NotImplementedError('_pre_analysis() is not implemented.')

    def _intra_analysis(self):
        raise NotImplementedError('_intra_analysis() is not implemented.')

    def _post_analysis(self):
        raise NotImplementedError('_post_analysis() is not implemented.')

    def _entry_key(self, entry):
        raise NotImplementedError('_entry_key() is not implemented.')

    def _get_successors(self, entry):
        raise NotImplementedError('_get_successors() is not implemented.')

    def _pre_entry_handling(self, entry):
        raise NotImplementedError('_pre_entry_handling() is not implemented.')

    def _post_entry_handling(self, entry, new_entries, successors):
        raise NotImplementedError('_post_entry_handling() is not implemented.')

    def _handle_successor(self, entry, successor, successors):
        raise NotImplementedError('_handle_successor() is not implemented.')

    def _entry_list_empty(self):
        raise NotImplementedError('_entry_list_empty() is not implemented.')

    def _get_initial_abstract_state(self, node):
        raise NotImplementedError('_get_initial_abstract_state() is not implemented.')

    def _merge_entries(self, *entries):
        raise NotImplementedError('_merge_entries() is not implemented.')

    def _merge_states(self, *states):
        """

        :param states: Abstract states to merge.
        :return:       A merged abstract state.
        """

        raise NotImplementedError('_merge_states() is not implemented.')

    def _should_widen_entries(self, *entries):
        raise NotImplementedError('_should_widen_entries() is not implemented.')

    def _widen_entries(self, *entries):
        raise NotImplementedError('_widen_entries() is not implemented.')

    def _widen_states(self, *states):
        raise NotImplementedError('_widen_states() is not implemented.')

    def _entry_sorting_key(self, entry):
        raise NotImplementedError('_entry_sorting_key() is not implemented.')

    def _run_on_node(self, node, state):
        raise NotImplementedError('_run_on_node() is not implemented.')

    #
    # Private methods
    #

    def _analyze(self):
        """
        The main analysis routine.

        :return: None
        """

        self._pre_analysis()

        if self._graph_visitor is None:
            # There is no base graph that we can rely on. The analysis itself should generate successors for the
            # current job.
            # An example is the CFG recovery.

            self._analysis_core_baremetal()

        else:
            # We have a base graph to follow. Just handle the current job.

            self._analysis_core_graph()

        self._post_analysis()

    def _analysis_core_graph(self):

        while not self.should_abort:

            self._intra_analysis()

            n = self._graph_visitor.next_node()

            if n is None:
                # all done!
                break

            entry_state = self._merge_state_from_predecessors(n)
            if entry_state is None:
                entry_state = self._get_initial_abstract_state(n)

            if n is None:
                break

            changed, output_state = self._run_on_node(n, entry_state)

            # record the new state
            self._state_map[n] = output_state

            if not changed:
                # reached a fixed point
                continue

            # add all successors
            self._graph_visitor.revisit(n, include_self=False)

    def _merge_state_from_predecessors(self, node):
        """
        Get abstract states for all predecessors of the node, merge them, and return the merged state.

        :param node: The node in graph.
        :return:     A merged state, or None if no predecessor is available.
        """

        preds = self._graph_visitor.predecessors(node)

        states = [ self._state_map[n] for n in preds ]

        if not states:
            return None

        return reduce(lambda s0, s1: self._merge_states(s0, s1), states[1:], states[0])

    def _analysis_core_baremetal(self):

        if not self._job_info_list:
            self._entry_list_empty()

        while not self.should_abort:

            if self._status_callback is not None:
                self._status_callback(self)

            # should_abort might be changed by the status callback function
            if self.should_abort:
                return

            if not self._job_info_list:
                self._entry_list_empty()

            if not self._job_info_list:
                # still no job available
                break

            job_info = self._job_info_list[0]

            try:
                self._pre_entry_handling(job_info.entry)
            except AngrDelayEntryNotice:
                # delay the handling of this job
                continue
            except AngrSkipEntryNotice:
                # consume and skip this job
                self._job_info_list = self._job_info_list[1:]
                continue

            self._job_info_list = self._job_info_list[1:]

            self._process_job_and_get_successors(job_info)

            # Short-cut for aborting the analysis
            if self.should_abort:
                break

            self._intra_analysis()

    def _process_job_and_get_successors(self, job_info):
        """
        Process a job, get all successors of this job, and call _handle_successor() to handle each successor.

        :param EntryInfo entry: The EntryInfo instance
        :return: None
        """

        job = job_info.entry

        successors = self._get_successors(job)

        all_new_entries = [ ]

        for successor in successors:
            new_entries = self._handle_successor(job, successor, successors)

            if new_entries:
                all_new_entries.extend(new_entries)

                for new_entry in new_entries:
                    self._insert_entry(new_entry)

        self._post_entry_handling(job, all_new_entries, successors)

    def _insert_entry(self, entry):
        """
        Insert a new entry into the entry list. If the entry list is ordered, this entry will be inserted at the
        correct position.

        :param entry: The entry to insert
        :return: None
        """

        key = self._entry_key(entry)

        if self._allow_merging:
            if key in self._entries_map:
                entry_info = self._entries_map[key]

                # decide if we want to trigger a widening
                # if not, we'll simply do the merge
                # TODO: save all previous entries for the sake of widening
                entry_added = False
                if self._allow_widening and self._should_widen_entries(entry_info.entry, entry):
                    try:
                        widened_entry = self._widen_entries(entry_info.entry, entry)
                        # remove the old job since now we have a widened one
                        if entry_info in self._job_info_list:
                            self._job_info_list.remove(entry_info)
                        entry_info.add_entry(widened_entry, widened=True)
                        entry_added = True
                    except AngrJobWideningFailureNotice:
                        # widening failed
                        # fall back to merging...
                        pass

                if not entry_added:
                    try:
                        merged_entry = self._merge_entries(entry_info.entry, entry)
                        # remove the old job since now we have a merged one
                        if entry_info in self._job_info_list:
                            self._job_info_list.remove(entry_info)
                        entry_info.add_entry(merged_entry, merged=True)
                    except AngrJobMergingFailureNotice:
                        # merging failed
                        entry_info = EntryInfo(key, entry)
                        # update the entries map
                        self._entries_map[key] = entry_info

            else:
                entry_info = EntryInfo(key, entry)
                self._entries_map[key] = entry_info

        else:
            entry_info = EntryInfo(key, entry)

        if self._order_entries:
            self._binary_insert(self._job_info_list, entry_info, lambda elem: self._entry_sorting_key(elem.entry))

        else:
            self._job_info_list.append(entry_info)

    def _peek_entry(self, pos):
        """
        Return the entry currently at position `pos`, but still keep it in the entry list. An IndexError will be raised
        if that position does not currently exist in the entry list.

        :param int pos: Position of the entry to get.
        :return: The entry
        """

        if pos < len(self._job_info_list):
            return self._job_info_list[pos].entry

        raise IndexError()

    #
    # Utils
    #

    @staticmethod
    def _binary_insert(lst, elem, key, lo=0, hi=None):
        """
        Insert an element into a sorted list, and keep the list sorted.

        The major difference from bisect.bisect_left is that this function supports a key method, so user doesn't have
        to create the key array for each insertion.

        :param list lst: The list. Must be pre-ordered.
        :param object element: An element to insert into the list.
        :param func key: A method to get the key for each element in the list.
        :param int lo: Lower bound of the search.
        :param int hi: Upper bound of the search.
        :return: None
        """

        if lo < 0:
            raise ValueError("lo must be a non-negative number")

        if hi is None:
            hi = len(lst)

        while lo < hi:
            mid = (lo + hi) // 2
            if key(lst[mid]) < key(elem):
                lo = mid + 1
            else:
                hi = mid

        lst.insert(lo, elem)
