import networkx

from functools import reduce

from ...errors import AngrForwardAnalysisError
from ...errors import AngrSkipJobNotice, AngrDelayJobNotice, AngrJobMergingFailureNotice, AngrJobWideningFailureNotice


from .job_info import JobInfo

class ForwardAnalysis:
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

        For compatibility reasons, the variable `changed` in the returning tuple can have three values:
        - True, means a change has occurred, the output state is not the same as the input state, and a fixed point is
          not reached. Usually used if the analysis performs weak updates.
        - False, means no change has occurred. Usually used if the analysis performs weak updates.
        - None, means no change detection is performed during this process (e.g., if the analysis requires strong
          updates), and change detection will be performed later during _merge_states().

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
        :return:       A merged abstract state, and a boolean variable indicating if a local fixed-point has reached (
                       i.e., union(state0, state1) == state0), in which case, its successors will not be revisited.
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
                break

            job_state = self._get_input_state(n)
            if job_state is None:
                job_state = self._initial_abstract_state(n)

            changed, output_state = self._run_on_node(n, job_state)

            # output state of node n is input state for successors to node n
            successors_to_visit = self._add_input_state(n, output_state)

            if changed is False:
                # no change is detected
                continue
            elif changed is True:
                # changes detected
                # revisit all its successors
                self._graph_visitor.revisit_successors(n, include_self=False)
            else:
                # the change of states are determined during state merging (_add_input_state()) instead of during
                # simulated execution (_run_on_node()).
                # revisit all successors in the `successors_to_visit` list
                for succ in successors_to_visit:
                    self._graph_visitor.revisit_node(succ)

    def _add_input_state(self, node, input_state):
        """
        Add the input state to all successors of the given node.

        :param node:        The node whose successors' input states will be touched.
        :param input_state: The state that will be added to successors of the node.
        :return:            None
        """

        successors = self._graph_visitor.successors(node)
        successors_to_visit = set()  # a collection of successors whose input states did not reach a fixed point

        for succ in successors:
            if succ in self._state_map:
                to_merge = [ self._state_map[succ], input_state ]
                r = self._merge_states(succ, *to_merge)
                if type(r) is tuple and len(r) == 2:
                    merged_state, reached_fixedpoint = r
                else:
                    # compatibility concerns
                    merged_state, reached_fixedpoint = r, False
                self._state_map[succ] = merged_state
            else:
                self._state_map[succ] = input_state
                reached_fixedpoint = False

            if not reached_fixedpoint:
                successors_to_visit.add(succ)

        return successors_to_visit

    def _pop_input_state(self, node):
        """
        Get the input abstract state for this node, and remove it from the state map.

        :param node: The node in graph.
        :return:     A merged state, or None if there is no input state for this node available.
        """

        if node in self._state_map:
            return self._state_map.pop(node)
        return None

    def _get_input_state(self, node):
        """
        Get the input abstract state for this node.

        :param node:    The node in graph.
        :return:        A merged state, or None if there is no input state for this node available.
        """

        return self._state_map.get(node, None)

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
