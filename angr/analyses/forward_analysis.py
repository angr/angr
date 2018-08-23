import networkx

from claripy.utils.orderedset import OrderedSet

from ..misc.ux import deprecated
# errors
from ..errors import AngrForwardAnalysisError
# notices
from ..errors import AngrSkipJobNotice, AngrDelayJobNotice, AngrJobMergingFailureNotice, \
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
        self._node_to_index = { }
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

    def nodes(self):
        """
        Return an iterator of nodes following an optimal traversal order.

        :return:
        """

        sorted_nodes = self.sort_nodes()

        return iter(sorted_nodes)

    @deprecated(replacement='nodes')
    def nodes_iter(self):
        """
        (Deprecated) Return an iterator of nodes following an optimal traversal order. Will be removed in the future.
        """
        return self.nodes()

    # Traversal

    def reset(self):
        """
        Reset the internal node traversal state. Must be called prior to visiting future nodes.

        :return: None
        """

        self._sorted_nodes.clear()
        self._node_to_index.clear()
        self._reached_fixedpoint.clear()

        for i, n in enumerate(self.sort_nodes()):
            self._node_to_index[n] = i
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
        self._sorted_nodes = OrderedSet(sorted(self._sorted_nodes, key=lambda n: self._node_to_index[n]))

    def reached_fixedpoint(self, node):
        """
        Mark a node as reached fixed-point. This node as well as all its successors will not be visited in the future.

        :param node: The node to mark as reached fixed-point.
        :return:     None
        """

        self._reached_fixedpoint.add(node)


class FunctionGraphVisitor(GraphVisitor):
    def __init__(self, func, graph=None):
        """

        :param knowledge.Function func:
        """

        super(FunctionGraphVisitor, self).__init__()

        self.function = func

        if graph is None:
            self.graph = self.function.graph
        else:
            self.graph = graph

        self.reset()

    def startpoints(self):

        return [ self.function.startpoint ]

    def successors(self, node):

        return list(self.graph.successors(node))

    def predecessors(self, node):

        return list(self.graph.predecessors(node))

    def sort_nodes(self, nodes=None):

        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.graph)

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

        return list(self.callgraph.successors(node))

    def predecessors(self, node):

        return list(self.callgraph.predecessors(node))

    def sort_nodes(self, nodes=None):

        sorted_nodes = CFGUtils.quasi_topological_sort_nodes(self.callgraph)

        if nodes is not None:
            sorted_nodes = [ n for n in sorted_nodes if n in set(nodes) ]

        return sorted_nodes


class SingleNodeGraphVisitor(GraphVisitor):
    def __init__(self, node):
        """

        :param node: The single node that should be in the graph.
        """

        super(SingleNodeGraphVisitor, self).__init__()

        self.node = node

        self.reset()

    def startpoints(self):
        return [ self.node.addr ]

    def successors(self, node):
        return [ ]

    def predecessors(self, node):
        return [ ]

    def sort_nodes(self, nodes=None):
        if nodes:
            return nodes
        else:
            return [ self.node ]


#
# Job info
#


class JobInfo(object):
    """
    Stores information of each job.
    """
    def __init__(self, key, job):
        self.key = key
        self.jobs = [(job, '')]

        self.narrowing_count = 0  # not used

    def __hash__(self):
        return hash(self.key)

    def __eq__(self, o):
        return type(self) == type(o) and \
               self.key == o.key

    def __repr__(self):
        s = "<JobInfo %s>" % (str(self.key))
        return s

    @property
    def job(self):
        """
        Get the latest available job.

        :return: The latest available job.
        """

        job, _ = self.jobs[-1]
        return job

    @property
    def merged_jobs(self):
        for job, job_type in self.jobs:
            if job_type == 'merged':
                yield job

    @property
    def widened_jobs(self):
        for job, job_type in self.jobs:
            if job_type == 'widened':
                yield job

    def add_job(self, job, merged=False, widened=False):
        """
        Appended a new job to this JobInfo node.
        :param job: The new job to append.
        :param bool merged: Whether it is a merged job or not.
        :param bool widened: Whether it is a widened job or not.
        """

        job_type = ''
        if merged:
            job_type = 'merged'
        elif widened:
            job_type = 'widened'
        self.jobs.append((job, job_type))


class ForwardAnalysis(object):
    """
    This is my very first attempt to build a static forward analysis framework that can serve as the base of multiple
    static analyses in angr, including CFG analysis, VFG analysis, DDG, etc.

    In short, ForwardAnalysis performs a forward data-flow analysis by traversing a graph, compute on abstract values,
    and store results in abstract states. The user can specify what graph to traverse, how a graph should be traversed,
    how abstract values and abstract states are defined, etc.

    ForwardAnalysis has a few options to toggle, making it suitable to be the base class of several different styles of
    forward data-flow analysis implementations.

    ForwardAnalysis supports a special mode when no graph is available for traversal (for example, when a CFG is being
    initialized and constructed, no other graph can be used). In that case, the graph traversal functionality is
    disabled, and the optimal graph traversal order is not guaranteed. The user can provide a job sorting method to
    sort the jobs in queue and optimize traversal order.

    Feel free to discuss with me (Fish) if you have any suggestions or complaints.
    """

    def __init__(self, order_jobs=False, allow_merging=False, allow_widening=False, status_callback=None,
                 graph_visitor=None
                 ):
        """
        Constructor

        :param bool order_jobs:     If all jobs should be ordered or not.
        :param bool allow_merging:  If job merging is allowed.
        :param bool allow_widening: If job widening is allowed.
        :param graph_visitor:       A graph visitor to provide successors.
        :type graph_visitor:        GraphVisitor or None
        :return: None
        """

        self._order_jobs = order_jobs
        self._allow_merging = allow_merging
        self._allow_widening = allow_widening
        self._status_callback = status_callback
        self._graph_visitor = graph_visitor

        # sanity checks
        if self._allow_widening and not self._allow_merging:
            raise AngrForwardAnalysisError('Merging must be allowed if widening is allowed.')

        # Analysis progress control
        self._should_abort = False

        # All remaining jobs
        self._job_info_queue = [ ]

        # A map between job key to job. Jobs with the same key will be merged by calling _merge_jobs()
        self._job_map = { }

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
    def jobs(self):
        for job_info in self._job_info_queue:
            yield job_info.job

    #
    # Public methods
    #

    def abort(self):
        """
        Abort the analysis
        :return: None
        """

        self._should_abort = True

    def has_job(self, job):
        """
        Checks whether there exists another job which has the same job key.
        :param job: The job to check.

        :return:    True if there exists another job with the same key, False otherwise.
        """
        job_key = self._job_key(job)
        return job_key in self._job_map

    #
    # Abstract interfaces
    #

    # Common interfaces

    def _pre_analysis(self):
        raise NotImplementedError('_pre_analysis() is not implemented.')

    def _intra_analysis(self):
        raise NotImplementedError('_intra_analysis() is not implemented.')

    def _post_analysis(self):
        raise NotImplementedError('_post_analysis() is not implemented.')

    def _job_key(self, job):
        raise NotImplementedError('_job_key() is not implemented.')

    def _get_successors(self, job):
        raise NotImplementedError('_get_successors() is not implemented.')

    def _pre_job_handling(self, job):
        raise NotImplementedError('_pre_job_handling() is not implemented.')

    def _post_job_handling(self, job, new_jobs, successors):
        raise NotImplementedError('_post_job_handling() is not implemented.')

    def _handle_successor(self, job, successor, successors):
        raise NotImplementedError('_handle_successor() is not implemented.')

    def _job_queue_empty(self):
        raise NotImplementedError('_job_queue_empty() is not implemented.')

    def _initial_abstract_state(self, node):
        raise NotImplementedError('_get_initial_abstract_state() is not implemented.')

    def _run_on_node(self, node, state):
        """
        The analysis routine that runs on each node in the graph.

        :param node:    A node in the graph.
        :param state:   An abstract state that acts as the initial abstract state of this analysis routine.
        :return:        A tuple: (changed, output abstract state)
        """

        raise NotImplementedError('_run_on_node() is not implemented.')

    def _merge_states(self, node, *states):
        """
        Merge multiple abstract states into one.

        :param node:   A node in the graph.
        :param states: Abstract states to merge.
        :return:       A merged abstract state.
        """

        raise NotImplementedError('_merge_states() is not implemented.')

    def _widen_states(self, *states):
        raise NotImplementedError('_widen_states() is not implemented.')

    # Special interfaces for non-graph-traversal mode

    def _merge_jobs(self, *jobs):
        raise NotImplementedError('_merge_jobs() is not implemented.')

    def _should_widen_jobs(self, *jobs):
        raise NotImplementedError('_should_widen_jobs() is not implemented.')

    def _widen_jobs(self, *jobs):
        raise NotImplementedError('_widen_jobs() is not implemented.')

    def _job_sorting_key(self, job):
        raise NotImplementedError('_job_sorting_key() is not implemented.')

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

            job_state = self._pop_input_state(n)
            if job_state is None:
                job_state = self._initial_abstract_state(n)

            if n is None:
                break

            changed, output_state = self._run_on_node(n, job_state)

            # output state of node n is input state for successors to node n
            self._add_input_state(n, output_state)

            if not changed:
                # reached a fixed point
                continue

            # add all successors
            self._graph_visitor.revisit(n, include_self=False)

    def _add_input_state(self, node, input_state):
        """
        Add the input state to all successors of the given node.

        :param node:        The node whose successors' input states will be touched.
        :param input_state: The state that will be added to successors of the node.
        :return:            None
        """

        successors = self._graph_visitor.successors(node)

        for succ in successors:
            if succ in self._state_map:
                self._state_map[succ] = self._merge_states(succ, *([ self._state_map[succ], input_state ]))
            else:
                self._state_map[succ] = input_state

    def _pop_input_state(self, node):
        """
        Get the input abstract state for this node, and remove it from the state map.

        :param node: The node in graph.
        :return:     A merged state, or None if there is no input state for this node available.
        """

        if node in self._state_map:
            return self._state_map.pop(node)
        return None

    def _merge_state_from_predecessors(self, node):
        """
        Get abstract states for all predecessors of the node, merge them, and return the merged state.

        :param node: The node in graph.
        :return:     A merged state, or None if no predecessor is available.
        """

        preds = self._graph_visitor.predecessors(node)

        states = [ self._state_map[n] for n in preds if n in self._state_map ]

        if not states:
            return None

        return reduce(lambda s0, s1: self._merge_states(node, s0, s1), states[1:], states[0])

    def _analysis_core_baremetal(self):

        if not self._job_info_queue:
            self._job_queue_empty()

        while not self.should_abort:

            if self._status_callback is not None:
                self._status_callback(self)

            # should_abort might be changed by the status callback function
            if self.should_abort:
                return

            if not self._job_info_queue:
                self._job_queue_empty()

            if not self._job_info_queue:
                # still no job available
                break

            job_info = self._job_info_queue[0]

            try:
                self._pre_job_handling(job_info.job)
            except AngrDelayJobNotice:
                # delay the handling of this job
                continue
            except AngrSkipJobNotice:
                # consume and skip this job
                self._job_info_queue = self._job_info_queue[1:]
                self._job_map.pop(self._job_key(job_info.job), None)
                continue

            # remove the job info from the map
            self._job_map.pop(self._job_key(job_info.job), None)

            self._job_info_queue = self._job_info_queue[1:]

            self._process_job_and_get_successors(job_info)

            # Short-cut for aborting the analysis
            if self.should_abort:
                break

            self._intra_analysis()

    def _process_job_and_get_successors(self, job_info):
        """
        Process a job, get all successors of this job, and call _handle_successor() to handle each successor.

        :param JobInfo job_info: The JobInfo instance
        :return: None
        """

        job = job_info.job

        successors = self._get_successors(job)

        all_new_jobs = [ ]

        for successor in successors:
            new_jobs = self._handle_successor(job, successor, successors)

            if new_jobs:
                all_new_jobs.extend(new_jobs)

                for new_job in new_jobs:
                    self._insert_job(new_job)

        self._post_job_handling(job, all_new_jobs, successors)

    def _insert_job(self, job):
        """
        Insert a new job into the job queue. If the job queue is ordered, this job will be inserted at the correct
        position.

        :param job: The job to insert
        :return:    None
        """

        key = self._job_key(job)

        if self._allow_merging:
            if key in self._job_map:
                job_info = self._job_map[key]

                # decide if we want to trigger a widening
                # if not, we'll simply do the merge
                # TODO: save all previous jobs for the sake of widening
                job_added = False
                if self._allow_widening and self._should_widen_jobs(job_info.job, job):
                    try:
                        widened_job = self._widen_jobs(job_info.job, job)
                        # remove the old job since now we have a widened one
                        if job_info in self._job_info_queue:
                            self._job_info_queue.remove(job_info)
                        job_info.add_job(widened_job, widened=True)
                        job_added = True
                    except AngrJobWideningFailureNotice:
                        # widening failed
                        # fall back to merging...
                        pass

                if not job_added:
                    try:
                        merged_job = self._merge_jobs(job_info.job, job)
                        # remove the old job since now we have a merged one
                        if job_info in self._job_info_queue:
                            self._job_info_queue.remove(job_info)
                        job_info.add_job(merged_job, merged=True)
                    except AngrJobMergingFailureNotice:
                        # merging failed
                        job_info = JobInfo(key, job)
                        # update the job map
                        self._job_map[key] = job_info

            else:
                job_info = JobInfo(key, job)
                self._job_map[key] = job_info

        else:
            job_info = JobInfo(key, job)
            self._job_map[key] = job_info

        if self._order_jobs:
            self._binary_insert(self._job_info_queue, job_info, lambda elem: self._job_sorting_key(elem.job))

        else:
            self._job_info_queue.append(job_info)

    def _peek_job(self, pos):
        """
        Return the job currently at position `pos`, but still keep it in the job queue. An IndexError will be raised
        if that position does not currently exist in the job list.

        :param int pos: Position of the job to get.
        :return:        The job
        """

        if pos < len(self._job_info_queue):
            return self._job_info_queue[pos].job

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
